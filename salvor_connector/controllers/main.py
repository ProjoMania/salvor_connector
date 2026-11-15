"""Salvor Connector protocol endpoints, v1 + v2 (see docs/CONNECTOR-PROTOCOL.md).

Every endpoint: POST only, auth="none", csrf=False, bearer token compared in
constant time against sha256(token) stored in the database named by
X-Salvor-Db, source-IP allowlist, one backup at a time per database.

v2 moves the work out of the HTTP request: backup/start launches a detached
runner (tools.spawn_runner / jobrunner.py) that writes the archive to a 0600
file under data_dir; Salvor polls backup/status and fetches the file with
backup/download in byte ranges, so no single request lives long enough for
limit_time_real or a proxy timeout to matter. Restore drills were removed in
2.0.4: the drill routes are 410 stubs; drop still removes leftover drill
databases that 2.0.0/2.0.1 created (oid-checked).
"""
import hmac
import json
import logging
import os
import re
import secrets
import time

import odoo
from odoo import SUPERUSER_ID, api, fields, http, release
from odoo.http import request, Response
from odoo.modules.registry import Registry
from odoo.tools import config

from .. import dbcompat
from .. import tools
from ..tools import (BACKUP_DISK_MARGIN, CAPABILITIES, DBNAME_RE, DRILL_RE,
                     PROTOCOL_VERSION, PROTOCOLS_SUPPORTED, DbLock, ip_allowed, sha256_hex,
                     stream_odoo_zip, stream_pg_dump)
from odoo.tools.misc import find_pg_tool

_logger = logging.getLogger(__name__)

MAX_JSON_BODY = 64 * 1024
CONFIG_MODEL = "salvor.connector.config"
LOG_MODEL = "salvor.connector.log"
DRILL_MODEL = "salvor.connector.drill"
MAX_STORED_JOBS = 2  # backup archives kept per database, the new one included
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ROUTE_OPTS = {"type": "http", "auth": "none", "csrf": False, "methods": ["POST"], "save_session": False, "readonly": False}
# drills are disabled (2.0.2): refuse any upload body before Odoo parses or spools it
UPLOAD_OPTS = dict(ROUTE_OPTS, max_content_length=1024)


class SalvorError(Exception):
    def __init__(self, status, code, message, **extra):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra


def _json(data, status=200):
    return Response(json.dumps(data), status=status, content_type="application/json; charset=utf-8",
                    headers=[("Cache-Control", "no-store")])


def _remote_addr():
    environ = request.httprequest.environ
    # ProxyFix (applied by Odoo only in proxy_mode) keeps the socket peer here.
    addr = environ.get("werkzeug.proxy_fix.orig", {}).get("REMOTE_ADDR") or environ.get("REMOTE_ADDR")
    if config.get("proxy_mode"):
        xff = environ.get("HTTP_X_FORWARDED_FOR")
        if xff:
            # Right-most entry = address seen by our own (trusted) proxy.
            addr = xff.split(",")[-1].strip()
    return addr or ""


def _module_installed_raw(dbname):
    """Check the module state without building a registry for foreign dbs."""
    if dbname in Registry.registries:
        return CONFIG_MODEL in Registry.registries[dbname]
    try:
        with odoo.sql_db.db_connect(dbname).cursor() as cr:
            cr.execute("SELECT state FROM ir_module_module WHERE name = 'salvor_connector'")
            row = cr.fetchone()
            return bool(row and row[0] in ("installed", "to upgrade"))
    except Exception:  # noqa: BLE001 - not an Odoo db / no access
        return False


REFUSALS_PER_MINUTE = 30


class SalvorConnectorController(http.Controller):

    # ------------------------------------------------------------------ core
    def _context(self, endpoint):
        """Resolve db, check token/IP/enabled. Returns (dbname, registry, settings dict).

        Until a valid token is presented every refusal is the same 401
        "unauthorized" — unknown database, module not installed, not paired or
        wrong token — so an anonymous caller cannot probe which database names
        exist (list_db=False stays meaningful). Only a caller holding this
        database's token learns about IP/disabled refusals.
        """
        auth = request.httprequest.headers.get("Authorization") or ""
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        presented = sha256_hex(token) if token else ""
        dbname = (request.httprequest.headers.get("X-Salvor-Db") or "").strip()
        settings = None
        registry = None
        if dbname and DBNAME_RE.match(dbname) and dbname in dbcompat.list_dbs() \
                and _module_installed_raw(dbname):
            registry = Registry(dbname)
            if CONFIG_MODEL in registry:
                with registry.cursor() as cr:
                    env = api.Environment(cr, SUPERUSER_ID, {})
                    rec = env[CONFIG_MODEL]._get_singleton()
                    settings = {
                        "token_hash": rec.token_hash or "",
                        "allowed_ips": rec.allowed_ips or "",
                        "enabled": rec.enabled,
                        "drill_enabled": rec.drill_enabled,
                        "module_version": rec._module_version(),
                    }
        stored = (settings or {}).get("token_hash") or "0" * 64  # same compare cost on a miss
        if not (hmac.compare_digest(presented.encode(), stored.encode()) and settings
                and settings["token_hash"] and presented):
            raise SalvorError(401, "unauthorized",
                              "Unauthorized: unknown database, connector not paired, or invalid token")
        if not ip_allowed(_remote_addr(), settings["allowed_ips"]):
            raise SalvorError(403, "ip_forbidden", "Source address not allowed")
        if not settings["enabled"]:
            raise SalvorError(403, "disabled", "Connector is disabled")
        return dbname, registry, settings

    def _audit(self, dbname, endpoint, status, result="ok", detail="", job_id=None, nbytes=None):
        """One salvor.connector.log row (never the token), visible in
        Settings → Salvor Connector → Pull Log; touch last_call_at."""
        addr = _remote_addr()
        _logger.info("salvor_connector %s -> %s %s from %s %s", endpoint, status, result, addr, detail or "")
        if not dbname:
            return
        try:
            registry = Registry.registries[dbname] if dbname in Registry.registries else None
            if registry is None or LOG_MODEL not in registry:
                return
            with registry.cursor() as cr:
                if status >= 400:
                    # at most REFUSALS_PER_MINUTE refusal rows per db per minute, counted
                    # in the db itself (all workers share it): floods go to the server log only
                    cr.execute("SELECT count(*) FROM salvor_connector_log WHERE http_status >= 400 "
                               "AND date > (now() at time zone 'UTC') - interval '1 minute'")
                    if cr.fetchone()[0] >= REFUSALS_PER_MINUTE:
                        return
                env = api.Environment(cr, SUPERUSER_ID, {})
                env[LOG_MODEL].sudo().create({
                    "endpoint": endpoint,
                    "http_status": status,
                    "result": result,
                    "remote_addr": addr[:64],
                    "job_id": job_id or False,
                    "bytes": nbytes or 0,
                    "detail": (detail or "")[:500],
                })
                if status < 400:
                    env[CONFIG_MODEL]._get_singleton().write({"last_call_at": fields.Datetime.now()})
        except Exception:  # noqa: BLE001 - auditing must never break the call
            _logger.exception("salvor_connector: audit failed")

    def _json_body(self):
        data = request.httprequest.get_data(cache=False, as_text=False, parse_form_data=False)
        if len(data) > MAX_JSON_BODY:
            raise SalvorError(422, "bad_args", "Body too large")
        if not data:
            # body already consumed as a form (non-JSON content type): accept form fields
            return {k: v for k, v in request.httprequest.form.items()}
        try:
            body = json.loads(data)
        except ValueError:
            raise SalvorError(422, "bad_args", "Body must be JSON") from None
        if not isinstance(body, dict):
            raise SalvorError(422, "bad_args", "Body must be a JSON object")
        return body

    def _handle(self, endpoint, func):
        dbname = None
        try:
            dbname, registry, settings = self._context(endpoint)
            return func(dbname, registry, settings)
        except SalvorError as e:
            # only audit into the db once we know it really hosts the connector
            self._audit(dbname or self._known_db(), endpoint, e.status, e.code, e.message[:200])
            return _json(dict(e.extra, error=e.code, message=e.message), e.status)

    @staticmethod
    def _known_db():
        name = (request.httprequest.headers.get("X-Salvor-Db") or "").strip()
        return name if DBNAME_RE.match(name or "") and name in Registry.registries else None

    # ------------------------------------------------------------- endpoints
    @http.route("/salvor/v1/info", **ROUTE_OPTS)
    def info(self, **kw):
        def run(dbname, registry, settings):
            with registry.cursor() as cr:
                cr.execute("SELECT pg_database_size(current_database())")
                db_size = cr.fetchone()[0]
                cr.execute("SELECT COALESCE(SUM(file_size), 0) FROM ir_attachment WHERE store_fname IS NOT NULL")
                fs_size = cr.fetchone()[0]
            self._audit(dbname, "info", 200)
            return _json({
                "protocol": PROTOCOL_VERSION,
                "module_version": settings["module_version"],
                "odoo_version": release.version,
                "db": dbname,
                "db_size_bytes": int(db_size),
                "filestore_bytes_estimate": int(fs_size),
                "drill_enabled": False,  # 2.0.2: connector drills are disabled
                "protocols": PROTOCOLS_SUPPORTED,
                "capabilities": CAPABILITIES,
                "data_dir_free_bytes": int(tools.disk_free(config["data_dir"])),
            })
        return self._handle("info", run)

    @http.route("/salvor/v1/backup", **ROUTE_OPTS)
    def backup(self, **kw):
        def run(dbname, registry, settings):
            fmt = self._json_body().get("format", "dump")
            if fmt not in ("dump", "zip"):
                raise SalvorError(422, "bad_args", "format must be 'dump' or 'zip'")
            lock = DbLock(dbname)
            if not lock.acquire():
                raise SalvorError(409, "busy", "Another backup or restore is running for this database")
            try:
                if fmt == "zip":
                    with registry.cursor() as cr:
                        manifest = dbcompat.dump_manifest(cr)
                    chunks = stream_odoo_zip(dbname, manifest)
                else:
                    chunks = stream_pg_dump(dbname)
            except Exception:
                lock.release()
                raise
            self._audit(dbname, "backup", 200, detail="v1 streamed, format=%s" % fmt)

            token_hash = settings["token_hash"]

            def still_authorized():
                """Revocation/disconnect/disable during a long v1 stream stops it."""
                try:
                    with registry.cursor() as cr:
                        cr.execute("SELECT token_hash, enabled FROM salvor_connector_config ORDER BY id LIMIT 1")
                        row = cr.fetchone()
                    return bool(row and row[0] == token_hash and row[1])
                except Exception:  # noqa: BLE001
                    return False

            def generate():
                ok = False
                checked = time.time()
                try:
                    for chunk in chunks:
                        if time.time() - checked > 30:
                            checked = time.time()
                            if not still_authorized():
                                _logger.warning("salvor_connector: token revoked during backup of %s; stopping", dbname)
                                return
                        yield chunk
                    ok = True
                finally:
                    lock.release()
                    _logger.info("salvor_connector backup %s format=%s %s", dbname, fmt,
                                 "completed" if ok else "ABORTED")

            filename = "%s.%s" % (dbname, "dump" if fmt == "dump" else "zip")
            return Response(generate(), status=200, direct_passthrough=True, headers=[
                ("Content-Type", "application/octet-stream"),
                ("Content-Disposition", 'attachment; filename="%s"' % filename),
                ("X-Salvor-Format", fmt),
                ("Cache-Control", "no-store"),
                ("X-Accel-Buffering", "no"),
            ])
        return self._handle("backup", run)

    # ------------------------------------------------------- v2: backup job
    @http.route("/salvor/v1/backup/start", **ROUTE_OPTS)
    def backup_start(self, **kw):
        def run(dbname, registry, settings):
            fmt = self._json_body().get("format", "dump")
            if fmt not in ("dump", "zip"):
                raise SalvorError(422, "bad_args", "format must be 'dump' or 'zip'")
            with registry.cursor() as cr:
                env = api.Environment(cr, SUPERUSER_ID, {})
                ttl = env[CONFIG_MODEL]._job_ttl_hours()
                cr.execute("SELECT pg_database_size(current_database())")
                db_size = cr.fetchone()[0]
                fs_size = 0
                manifest = None
                if fmt == "zip":
                    cr.execute("SELECT COALESCE(SUM(file_size), 0) FROM ir_attachment WHERE store_fname IS NOT NULL")
                    fs_size = cr.fetchone()[0]
                    manifest = dbcompat.dump_manifest(cr)
            tools.sweep_jobs(dbname, ttl)
            # pg_dump output is smaller than the live db; attachments are stored as-is in a zip
            estimate = int(db_size) + int(fs_size)
            free = tools.disk_free(config["data_dir"])
            if free < estimate + BACKUP_DISK_MARGIN:
                raise SalvorError(507, "insufficient_disk",
                                  "Not enough free disk in the Odoo data_dir for the backup file",
                                  free_bytes=int(free), required_bytes=int(estimate + BACKUP_DISK_MARGIN))
            lock = DbLock(dbname)
            if not lock.acquire():
                raise SalvorError(409, "busy", "Another backup or restore is running for this database")
            try:
                tools.trim_jobs(dbname, MAX_STORED_JOBS - 1)
                job_id = secrets.token_hex(16)
                path = tools.job_dir(dbname, job_id)
                tools._private_dir(tools.jobs_root(dbname))
                tools._private_dir(path)
                spec = {
                    "kind": "backup",
                    "format": fmt,
                    "db": dbname,
                    "pg_dump": find_pg_tool("pg_dump"),
                    "filestore": config.filestore(dbname) if fmt == "zip" else "",
                    "manifest": manifest,
                    "estimate_bytes": estimate,
                }
                tools.spawn_runner(path, spec, lock=lock)
            finally:
                lock.release()  # no-op once handed to the runner
            self._audit(dbname, "backup/start", 202, detail="format=%s estimate=%s" % (fmt, estimate), job_id=job_id)
            return _json({"job_id": job_id, "state": "running", "format": fmt,
                          "estimate_bytes": estimate, "expires_in_hours": ttl}, 202)
        return self._handle("backup/start", run)

    def _job(self, dbname):
        job_id = str(self._json_body().get("job_id") or "")
        path = tools.job_dir(dbname, job_id)
        if not path or not os.path.isdir(path):
            raise SalvorError(404, "job_not_found", "Unknown or expired backup job")
        return job_id, path

    @staticmethod
    def _job_out(job_id, path, state):
        archive = os.path.join(path, "archive")
        size = os.path.getsize(archive) if os.path.exists(archive) else 0
        out = {
            "job_id": job_id,
            "state": "running" if state.get("state") == "starting" else state.get("state", "running"),
            "format": None,
            "bytes": int(state.get("bytes") or size) if state.get("state") == "done" else size,
            "sha256": state.get("sha256") if state.get("state") == "done" else None,
            "error": state.get("error"),
            "started_at": state.get("started_at"),
            "finished_at": state.get("finished_at"),
        }
        return out

    @http.route("/salvor/v1/backup/status", **ROUTE_OPTS)
    def backup_status(self, **kw):
        def run(dbname, registry, settings):
            job_id, path = self._job(dbname)
            state = tools.live_state(path)
            out = self._job_out(job_id, path, state)
            try:
                with open(os.path.join(path, "job.json"), encoding="utf-8") as fh:
                    out["format"] = json.load(fh).get("format")
            except (OSError, ValueError):
                pass
            if out["state"] in ("done", "failed") and not state.get("audited"):
                tools.write_state(path, audited=True)
                self._audit(dbname, "backup/job", 200 if out["state"] == "done" else 500,
                            out["state"] if out["state"] == "done" else "job_failed",
                            detail=(out["error"] or "sha256=%s" % out["sha256"]), job_id=job_id, nbytes=out["bytes"])
            return _json(out)
        return self._handle("backup/status", run)

    @http.route("/salvor/v1/backup/download", **ROUTE_OPTS)
    def backup_download(self, **kw):
        def run(dbname, registry, settings):
            job_id, path = self._job(dbname)
            state = tools.live_state(path)
            if state.get("state") != "done":
                raise SalvorError(409, "not_ready", "The backup job has not finished", state=state.get("state"))
            archive = os.path.join(path, "archive")
            size = os.path.getsize(archive)
            try:
                rng = tools.parse_range(request.httprequest.headers.get("Range"), size)
            except ValueError:
                self._audit(dbname, "backup/download", 416, "bad_range", job_id=job_id)
                return Response(status=416, headers=[("Content-Range", "bytes */%d" % size)])
            start, end = rng if rng else (0, size - 1)
            length = end - start + 1 if size else 0
            headers = [
                ("Content-Type", "application/octet-stream"),
                ("Content-Length", str(length)),
                ("Accept-Ranges", "bytes"),
                ("ETag", '"%s"' % state["sha256"]),
                ("X-Salvor-Sha256", state["sha256"]),
                ("X-Salvor-Size", str(size)),
                ("Cache-Control", "no-store"),
                ("X-Accel-Buffering", "no"),
            ]
            if rng:
                headers.append(("Content-Range", "bytes %d-%d/%d" % (start, end, size)))
            self._audit(dbname, "backup/download", 206 if rng else 200,
                        detail="bytes %d-%d/%d" % (start, end, size), job_id=job_id, nbytes=length)
            return Response(tools.iter_file(archive, start, length), status=206 if rng else 200,
                            headers=headers, direct_passthrough=True)
        return self._handle("backup/download", run)

    @http.route("/salvor/v1/backup/cleanup", **ROUTE_OPTS)
    def backup_cleanup(self, **kw):
        def run(dbname, registry, settings):
            job_id, path = self._job(dbname)
            state = tools.read_state(path)
            if state.get("state") in ("starting", "running"):
                tools.terminate_state(state)
            tools.remove_tree(path)
            self._audit(dbname, "backup/cleanup", 200, job_id=job_id)
            return _json({"ok": True, "job_id": job_id})
        return self._handle("backup/cleanup", run)

    # ------------------------------------------------------------ drills
    def _drill_record(self, registry, name):
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            rec = env[DRILL_MODEL].search([("name", "=", name), ("state", "!=", "dropped")], limit=1)
            return rec.id or None, rec.state or None

    def _drill_write(self, registry, rec_id, **vals):
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            env[DRILL_MODEL].browse(rec_id).write(vals)

    def _drill_owned(self, registry, name):
        """Ownership = our record for that name AND the very database we created
        (same pg_database.oid). A name freed and re-created by someone else is
        not ours: the stale record is closed and the call refused."""
        rec_id, state = self._drill_record(registry, name)
        if rec_id:
            with registry.cursor() as cr:
                cr.execute("SELECT pg_oid FROM salvor_connector_drill WHERE id = %s", (rec_id,))
                stored = cr.fetchone()[0]
            if not stored or tools.db_oid(name) != stored:
                self._drill_write(registry, rec_id, state="dropped", dropped_at=fields.Datetime.now(),
                                  error="database gone or replaced outside the connector")
                rec_id = None
        if not rec_id:
            # Not created by THIS database's connector: refuse, whatever exists on the cluster.
            raise SalvorError(404, "db_not_found", "No drill database of that name was created by this connector")
        return rec_id, state

    # Removed in 2.0.4: the restore code path (drill restores through psql) is
    # gone from the module. The routes stay as stubs so an old Salvor worker gets
    # a clear answer; they never read the body (upload keeps a 1 KiB limit: 413).
    @staticmethod
    def _drills_removed():
        return _json({"error": "drills_removed",
                      "message": "Restore drills were removed from the Salvor Connector in 2.0.4"}, 410)

    @http.route("/salvor/v1/drill/start", **ROUTE_OPTS)
    def drill_start(self, **kw):
        return self._drills_removed()

    @http.route("/salvor/v1/drill/upload", **UPLOAD_OPTS)
    def drill_upload(self, **kw):
        return self._drills_removed()

    @http.route("/salvor/v1/drill/restore", **ROUTE_OPTS)
    def drill_restore(self, **kw):
        return self._drills_removed()

    @http.route("/salvor/v1/drill/status", **ROUTE_OPTS)
    def drill_status(self, **kw):
        return self._drills_removed()

    @http.route("/salvor/v1/restore", **ROUTE_OPTS)
    def restore(self, **kw):
        return self._drills_removed()

    @http.route("/salvor/v1/drop", **ROUTE_OPTS)
    def drop(self, **kw):
        def run(dbname, registry, settings):
            # kept in 2.0.2 so leftovers of 2.0.0/2.0.1 drills can still be removed (oid-checked)
            name = str(self._json_body().get("name") or "").strip()
            self._check_drill_name(name, dbname)
            rec_id, rstate = self._drill_owned(registry, name)
            self._drop(registry, dbname, name, rec_id)
            self._audit(dbname, "drop", 200, detail="dropped=%s" % name)
            return _json({"ok": True, "db": name})
        return self._handle("drop", run)

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _check_drill_name(name, live_db):
        if not DRILL_RE.match(name or "") or name == live_db:
            raise SalvorError(422, "bad_args", "name must match ^salvor_drill_[a-z0-9_]{1,40}$")

    def _drop(self, registry, dbname, name, rec_id):
        """Drop an OWNED drill db under its per-db lock: stop a running restore,
        drop the database and its filestore, remove the upload, mark dropped."""
        assert DRILL_RE.match(name)
        if name in (dbname, getattr(request, "db", None)):
            raise SalvorError(422, "bad_args", "Refusing to drop the current database")
        path = tools.drill_dir(dbname, name)
        state = tools.read_state(path)
        if state.get("state") in ("starting", "running"):
            tools.terminate_state(state)
        lock = DbLock(name)
        deadline = time.time() + 30
        while not lock.acquire():
            if time.time() > deadline:
                raise SalvorError(409, "busy", "This drill database is busy")
            time.sleep(0.5)
        try:
            with registry.cursor() as cr:
                cr.execute("SELECT pg_oid FROM salvor_connector_drill WHERE id = %s", (rec_id,))
                stored = cr.fetchone()[0]
            current = tools.db_oid(name)
            if current and current != stored:
                # re-checked under the lock: never drop a database we did not create
                raise SalvorError(404, "db_not_found", "No drill database of that name was created by this connector")
            if current:
                dbcompat.drop_drill(name)
            tools.remove_tree(path)
            self._drill_write(registry, rec_id, state="dropped", dropped_at=fields.Datetime.now())
        finally:
            lock.release()
