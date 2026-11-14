"""Salvor Connector protocol v1 endpoints (see docs/CONNECTOR-PROTOCOL.md).

Every endpoint: POST only, auth="none", csrf=False, bearer token compared in
constant time against sha256(token) stored in the database named by
X-Salvor-Db, source-IP allowlist, one backup/restore at a time per database.
"""
import hmac
import json
import logging
import os
import tempfile

import odoo
from odoo import SUPERUSER_ID, api, fields, http, release
from odoo.http import request, Response
from odoo.modules.registry import Registry
from odoo.service import db as db_service
from odoo.tools import config

from ..tools import (DBNAME_RE, DRILL_RE, PROTOCOL_VERSION, DbLock, ip_allowed, sha256_hex,
                     stream_odoo_zip, stream_pg_dump)

_logger = logging.getLogger(__name__)

MAX_JSON_BODY = 64 * 1024
CONFIG_MODEL = "salvor.connector.config"
ROUTE_OPTS = {"type": "http", "auth": "none", "csrf": False, "methods": ["POST"], "save_session": False, "readonly": False}


def _unwrap(func):
    # odoo.service.db gates these behind list_db (check_db_management_enabled);
    # the connector authenticates by its own token, so call the inner function.
    return getattr(func, "__wrapped__", func)


class SalvorError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


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


class SalvorConnectorController(http.Controller):

    # ------------------------------------------------------------------ core
    def _context(self, endpoint):
        """Resolve db, check pairing/IP/token. Returns (dbname, registry, settings dict)."""
        dbname = (request.httprequest.headers.get("X-Salvor-Db") or "").strip()
        if not dbname or not DBNAME_RE.match(dbname):
            raise SalvorError(404, "db_not_found", "Unknown database")
        if dbname not in db_service.list_dbs(True) or not _module_installed_raw(dbname):
            raise SalvorError(404, "db_not_found", "Unknown database")
        registry = Registry(dbname)
        if CONFIG_MODEL not in registry:
            raise SalvorError(404, "db_not_found", "Unknown database")
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
        addr = _remote_addr()
        if not settings["token_hash"]:
            raise SalvorError(401, "not_paired", "Connector is not paired")
        if not ip_allowed(addr, settings["allowed_ips"]):
            raise SalvorError(403, "ip_forbidden", "Source address not allowed")
        auth = request.httprequest.headers.get("Authorization") or ""
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        presented = sha256_hex(token) if token else ""
        if not hmac.compare_digest(presented.encode(), settings["token_hash"].encode()):
            raise SalvorError(401, "bad_token", "Invalid token")
        if not settings["enabled"]:
            raise SalvorError(403, "disabled", "Connector is disabled")
        return dbname, registry, settings

    def _audit(self, dbname, endpoint, status, detail=""):
        """Write an ir.logging row (never contains the token) and touch last_call_at."""
        addr = _remote_addr()
        msg = "salvor_connector %s -> %s from %s %s" % (endpoint, status, addr, detail)
        _logger.info(msg.strip())
        if not dbname:
            return
        try:
            registry = Registry.registries[dbname] if dbname in Registry.registries else None
            if registry is None or CONFIG_MODEL not in registry:
                return
            with registry.cursor() as cr:
                env = api.Environment(cr, SUPERUSER_ID, {})
                env["ir.logging"].sudo().create({
                    "name": "salvor_connector",
                    "type": "server",
                    "dbname": dbname,
                    "level": "INFO" if status < 400 else "WARNING",
                    "message": msg.strip()[:2000],
                    "path": "/salvor/v1/" + endpoint,
                    "func": endpoint,
                    "line": str(status),
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
            return {}
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
            self._audit(dbname or self._known_db(), endpoint, e.status, e.code)
            return _json({"error": e.code, "message": e.message}, e.status)

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
                "drill_enabled": bool(settings["drill_enabled"]),
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
                        manifest = _unwrap(db_service.dump_db_manifest)(cr)
                    chunks = stream_odoo_zip(dbname, manifest)
                else:
                    chunks = stream_pg_dump(dbname)
            except Exception:
                lock.release()
                raise
            self._audit(dbname, "backup", 200, "format=%s started" % fmt)

            def generate():
                ok = False
                try:
                    yield from chunks
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

    @http.route("/salvor/v1/restore", **ROUTE_OPTS)
    def restore(self, **kw):
        def run(dbname, registry, settings):
            if not settings["drill_enabled"]:
                raise SalvorError(403, "drill_disabled", "Restore drills are not enabled in the connector")
            name = (request.httprequest.form.get("name") or "").strip()
            upload = request.httprequest.files.get("file")
            self._check_drill_name(name, dbname)
            if upload is None:
                raise SalvorError(422, "bad_args", "Missing file")
            if name in db_service.list_dbs(True):
                raise SalvorError(422, "bad_args", "Drill database already exists")
            lock = DbLock(dbname)
            if not lock.acquire():
                raise SalvorError(409, "busy", "Another backup or restore is running for this database")
            tmp = None
            try:
                fd, tmp = tempfile.mkstemp(prefix="salvor_restore_", suffix=".bin")
                with os.fdopen(fd, "wb") as fh:
                    upload.save(fh)
                try:
                    _unwrap(db_service.restore_db)(name, tmp, copy=True)
                except Exception as e:  # noqa: BLE001
                    _logger.warning("salvor_connector restore into %s failed: %s", name, e)
                    if name in db_service.list_dbs(True):
                        try:
                            self._drop(name)
                        except Exception:  # noqa: BLE001
                            _logger.exception("salvor_connector: cleanup of %s failed", name)
                    raise SalvorError(422, "restore_failed", "Restore failed") from None
            finally:
                lock.release()
                if tmp and os.path.exists(tmp):
                    os.unlink(tmp)
            self._audit(dbname, "restore", 200, "into=%s" % name)
            return _json({"ok": True, "db": name})
        return self._handle("restore", run)

    @http.route("/salvor/v1/drop", **ROUTE_OPTS)
    def drop(self, **kw):
        def run(dbname, registry, settings):
            name = str(self._json_body().get("name") or "").strip()
            self._check_drill_name(name, dbname)
            if name not in db_service.list_dbs(True):
                raise SalvorError(404, "db_not_found", "Drill database not found")
            self._drop(name)
            self._audit(dbname, "drop", 200, "dropped=%s" % name)
            return _json({"ok": True, "db": name})
        return self._handle("drop", run)

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _check_drill_name(name, live_db):
        if not DRILL_RE.match(name or "") or name == live_db:
            raise SalvorError(422, "bad_args", "name must match ^salvor_drill_[a-z0-9_]{1,40}$")

    @staticmethod
    def _drop(name):
        assert DRILL_RE.match(name)
        if name == getattr(request, "db", None):
            raise SalvorError(422, "bad_args", "Refusing to drop the current database")
        _unwrap(db_service.exp_drop)(name)
