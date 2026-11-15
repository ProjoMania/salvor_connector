import hashlib
import io
import os
import subprocess
import tempfile
import time
import zipfile
from contextlib import closing
from unittest.mock import patch

import psycopg2

from odoo.exceptions import UserError
from odoo.tests import HttpCase, tagged
from odoo.tools.misc import exec_pg_environ, find_pg_tool

from .. import dbcompat
from .. import tools
from ..tools import DbLock, sha256_hex

TOKEN = "t" * 20 + "0123456789abcdefghijklmnopqrstuv"
# drill dbs are cluster-wide: a per-run suffix lets 17/18/19/20 run in parallel on one server
RUN = "%s_%s" % (__import__("odoo").release.version_info[0], __import__("secrets").token_hex(3))


def drill_name(tag):
    return "salvor_drill_%s_%s" % (tag, RUN)


@tagged("post_install", "-at_install")
class TestSalvorConnector(HttpCase):

    def setUp(self):
        super().setUp()
        self.cfg = self.env["salvor.connector.config"]._get_singleton()
        self.cfg.write({
            "token_hash": sha256_hex(TOKEN),
            "allowed_ips": "127.0.0.1\n::1",
            "enabled": True,
            "drill_enabled": False,
        })
        self.authenticate(None, None)  # session bound to the test db (routing only)
        self.dbname = self.env.cr.dbname

    def _post(self, endpoint, json=None, token=TOKEN, db=None, stream=False, headers_extra=None, **kw):
        headers = dict(headers_extra or {}, **{"X-Salvor-Db": db or self.dbname})
        if token:
            headers["Authorization"] = "Bearer " + token
        return self.opener.post(self.base_url() + "/salvor/v1/" + endpoint, json=json if json is not None else {},
                                headers=headers, stream=stream, timeout=120, **kw)

    def _assert_error(self, resp, status, code):
        self.assertEqual(resp.status_code, status, resp.text[:300])
        self.assertEqual(resp.json()["error"], code)

    # --- refusals ---------------------------------------------------------
    def test_missing_and_wrong_token(self):
        self._assert_error(self._post("info", token=None), 401, "unauthorized")
        self._assert_error(self._post("info", token="nope"), 401, "unauthorized")
        self._assert_error(self._post("info", token=TOKEN + "x"), 401, "unauthorized")

    def test_get_not_allowed(self):
        resp = self.opener.get(self.base_url() + "/salvor/v1/info",
                               headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN})
        self.assertEqual(resp.status_code, 405)

    def test_wrong_ip(self):
        self.cfg.allowed_ips = "10.9.9.9"
        self._assert_error(self._post("info"), 403, "ip_forbidden")
        self.cfg.allowed_ips = False
        self._assert_error(self._post("info"), 403, "ip_forbidden")

    def test_not_paired(self):
        self.cfg.action_disconnect()
        self._assert_error(self._post("info"), 401, "unauthorized")

    def test_disabled(self):
        self.cfg.enabled = False
        self._assert_error(self._post("info"), 403, "disabled")

    def test_unknown_db(self):
        # no database-name oracle: unknown db, non-Odoo db, bad name, wrong token,
        # wrong IP without token — all the same 401 body
        bodies = set()
        for db in ("no_such_db_salvor_x", "../etc/passwd", "-h", "postgres", self.dbname):
            for tok in (None, "nope"):
                resp = self._post("info", db=db, token=tok)
                self.assertEqual(resp.status_code, 401, (db, tok))
                bodies.add(resp.text)
        self.cfg.allowed_ips = "10.9.9.9"
        resp = self._post("info", token="nope")
        self.assertEqual(resp.status_code, 401)
        bodies.add(resp.text)
        self.assertEqual(len(bodies), 1, bodies)

    def test_bad_drill_name(self):
        # drills disabled (default): restore and drop refused with 403
        self._assert_error(self._post("drop", json={"name": "salvor_drill_x"}), 403, "drill_disabled")
        self.cfg.drill_enabled = True
        self._assert_error(self._post("drop", json={"name": "salvor_drill_x"}), 404, "db_not_found")
        for bad in ("prod", self.dbname, "salvor_drill_", "salvor_drill_X", "salvor_drill_a;drop",
                    "salvor_drill_../a", "salvor_drill_" + "a" * 41):
            self._assert_error(self._post("drop", json={"name": bad}), 422, "bad_args")
        self.cfg.drill_enabled = False
        resp = self.opener.post(self.base_url() + "/salvor/v1/restore",
                                headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN},
                                data={"name": "salvor_drill_a"}, files={"backup_file": ("x.dump", b"PGDMP")})
        self._assert_error(resp, 403, "drill_disabled")
        self.cfg.drill_enabled = True
        resp = self.opener.post(self.base_url() + "/salvor/v1/restore",
                                headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN},
                                data={"name": self.dbname}, files={"backup_file": ("x.dump", b"PGDMP")})
        self._assert_error(resp, 422, "bad_args")

    def test_bad_format(self):
        self._assert_error(self._post("backup", json={"format": "tar"}), 422, "bad_args")

    # --- happy paths ------------------------------------------------------
    def test_info(self):
        resp = self._post("info", json={})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        data = resp.json()
        self.assertEqual(data["protocol"], 1)  # baseline: deployed Salvor (checks == 1) keeps working
        self.assertEqual(data["protocols"], [1, 2])
        self.assertIn("backup_job", data["capabilities"])
        self.assertEqual(data["db"], self.dbname)
        self.assertFalse(data["drill_enabled"])
        self.assertGreater(data["db_size_bytes"], 0)
        for key in ("module_version", "odoo_version", "filestore_bytes_estimate"):
            self.assertIn(key, data)
        self.env.invalidate_all()
        self.assertTrue(self.env["salvor.connector.log"].search_count(
            [("endpoint", "=", "info"), ("http_status", "=", 200)]))
        self._post("info", token="nope")
        refused = self.env["salvor.connector.log"].search([("endpoint", "=", "info"), ("http_status", "=", 401)])
        self.assertTrue(refused)
        self.assertEqual(refused[0].result, "unauthorized")
        logs = self.env["salvor.connector.log"].search([])
        blob = " ".join("%s %s %s" % (r.detail, r.result, r.endpoint) for r in logs)
        self.assertNotIn(TOKEN, blob)
        self.assertNotIn(sha256_hex(TOKEN), blob)

    def test_backup_dump_stream(self):
        resp = self._post("backup", json={"format": "dump"}, stream=True)
        self.assertEqual(resp.status_code, 200, resp.text[:300] if resp.status_code != 200 else "")
        self.assertEqual(resp.headers["X-Salvor-Format"], "dump")
        self.assertEqual(resp.headers["Content-Type"], "application/octet-stream")
        h, buf = hashlib.sha256(), io.BytesIO()
        for chunk in resp.iter_content(65536):
            h.update(chunk)
            buf.write(chunk)
        body = buf.getvalue()
        self.assertTrue(body.startswith(b"PGDMP"), body[:10])
        self.assertEqual(h.hexdigest(), hashlib.sha256(body).hexdigest())
        # the archive is a valid custom-format dump
        with tempfile.NamedTemporaryFile(suffix=".dump") as fh:
            fh.write(body)
            fh.flush()
            out = subprocess.run([find_pg_tool("pg_restore"), "--list", fh.name], env=exec_pg_environ(),
                                 capture_output=True, check=True)
            self.assertIn(b"ir_module_module", out.stdout)
        # lock released after the stream
        lock = DbLock(self.dbname)
        self.assertTrue(lock.acquire())
        lock.release()

    def test_backup_zip_stream(self):
        resp = self._post("backup", json={"format": "zip"}, stream=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["X-Salvor-Format"], "zip")
        body = b"".join(resp.iter_content(65536))
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = zf.namelist()
            self.assertEqual(names[0], "dump.sql")
            self.assertIn("manifest.json", names)
            self.assertIsNone(zf.testzip())
            self.assertIn(b"PostgreSQL database dump", zf.read("dump.sql")[:400])

    def test_busy(self):
        lock = DbLock(self.dbname)
        self.assertTrue(lock.acquire())
        try:
            self._assert_error(self._post("backup", json={"format": "dump"}), 409, "busy")
        finally:
            lock.release()

    # --- v2 backup job ------------------------------------------------------
    def _run_job(self, fmt):
        resp = self._post("backup/start", json={"format": fmt})
        self.assertEqual(resp.status_code, 202, resp.text[:300])
        job_id = resp.json()["job_id"]
        self.addCleanup(lambda: self._post("backup/cleanup", json={"job_id": job_id}))
        deadline = time.time() + 180
        while True:
            st = self._post("backup/status", json={"job_id": job_id}).json()
            if st["state"] in ("done", "failed") or time.time() > deadline:
                break
            time.sleep(0.5)
        self.assertEqual(st["state"], "done", st)
        self.assertEqual(st["format"], fmt)
        return job_id, st

    def test_backup_job_dump_range_resume(self):
        job_id, st = self._run_job("dump")
        # the per-db lock is free once the runner exited
        lock = DbLock(self.dbname)
        self.assertTrue(lock.acquire())
        lock.release()
        full = self._post("backup/download", json={"job_id": job_id})
        self.assertEqual(full.status_code, 200)
        body = full.content
        self.assertEqual(len(body), st["bytes"])
        self.assertEqual(hashlib.sha256(body).hexdigest(), st["sha256"])
        self.assertEqual(full.headers["X-Salvor-Sha256"], st["sha256"])
        self.assertTrue(body.startswith(b"PGDMP"))
        # an interrupted transfer resumes from where it stopped
        cut = len(body) // 3
        part1 = self._post("backup/download", json={"job_id": job_id}, stream=True)
        got = b""
        for chunk in part1.iter_content(1024):
            got += chunk
            if len(got) >= cut:
                break
        part1.close()
        got = got[:cut]
        part2 = self._post("backup/download", json={"job_id": job_id}, headers_extra={"Range": "bytes=%d-" % cut})
        self.assertEqual(part2.status_code, 206)
        self.assertEqual(part2.headers["Content-Range"], "bytes %d-%d/%d" % (cut, len(body) - 1, len(body)))
        self.assertEqual(hashlib.sha256(got + part2.content).hexdigest(), st["sha256"])
        bad = self._post("backup/download", json={"job_id": job_id},
                         headers_extra={"Range": "bytes=%d-" % (len(body) + 5)})
        self.assertEqual(bad.status_code, 416)
        with tempfile.NamedTemporaryFile(suffix=".dump") as fh:
            fh.write(body)
            fh.flush()
            out = subprocess.run([find_pg_tool("pg_restore"), "--list", fh.name], env=exec_pg_environ(),
                                 capture_output=True, check=True)
            self.assertIn(b"ir_module_module", out.stdout)
        # cleanup removes the file; the job is gone afterwards
        self.assertEqual(self._post("backup/cleanup", json={"job_id": job_id}).status_code, 200)
        self._assert_error(self._post("backup/status", json={"job_id": job_id}), 404, "job_not_found")
        self.assertTrue(self.env["salvor.connector.log"].search_count(
            [("endpoint", "=", "backup/download"), ("job_id", "=", job_id)]))

    def test_backup_job_zip(self):
        job_id, st = self._run_job("zip")
        body = self._post("backup/download", json={"job_id": job_id}).content
        self.assertEqual(hashlib.sha256(body).hexdigest(), st["sha256"])
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            self.assertEqual(zf.namelist()[0], "dump.sql")
            self.assertIn("manifest.json", zf.namelist())
            self.assertIsNone(zf.testzip())

    def test_job_ids_are_scoped(self):
        for bad in ("", "../../etc", "0" * 31, "g" * 32, "0" * 32):
            self._assert_error(self._post("backup/status", json={"job_id": bad}), 404, "job_not_found")
            self._assert_error(self._post("backup/download", json={"job_id": bad}), 404, "job_not_found")
        self._assert_error(self._post("backup/start", json={"format": "tar"}), 422, "bad_args")

    def test_backup_job_busy_and_disk(self):
        lock = DbLock(self.dbname)
        self.assertTrue(lock.acquire())
        try:
            self._assert_error(self._post("backup/start", json={"format": "dump"}), 409, "busy")
        finally:
            lock.release()
        with patch.object(tools, "disk_free", return_value=1024):
            resp = self._post("backup/start", json={"format": "dump"})
            self._assert_error(resp, 507, "insufficient_disk")
            self.assertIn("required_bytes", resp.json())

    def test_job_expiry(self):
        job_id, st = self._run_job("dump")
        path = tools.job_dir(self.dbname, job_id)
        tools.write_state(path, spawned_at=time.time() - 25 * 3600)
        self.env["salvor.connector.config"]._cron_housekeeping()
        self._assert_error(self._post("backup/status", json={"job_id": job_id}), 404, "job_not_found")

    # --- drills -------------------------------------------------------------
    def _drill_db_exists(self, name):
        return dbcompat.pg_db_exists(name)

    def _force_drop(self, name):
        if dbcompat.pg_db_exists(name):
            dbcompat.drop_drill(name)

    def test_drill_v2_roundtrip_neutralized(self):
        self.cfg.drill_enabled = True
        job_id, st = self._run_job("dump")
        archive = self._post("backup/download", json={"job_id": job_id}).content
        name = drill_name("ut_v2")
        self._force_drop(name)
        self.addCleanup(self._force_drop, name)
        resp = self._post("drill/start", json={"name": name, "size": len(archive)})
        self.assertEqual(resp.status_code, 201, resp.text[:300])
        self.assertTrue(self._drill_db_exists(name))
        # a second claim of the same name is a conflict, never a second owner
        self._assert_error(self._post("drill/start", json={"name": name, "size": 10}), 409, "drill_exists")
        half = len(archive) // 2
        self._upload(name, 0, archive[:half])
        self._upload(name, 0, archive[:half])  # a retried chunk replaces itself
        resp = self._upload(name, half + 10, archive[half + 10:half + 20], expect=409)
        self.assertEqual(resp.json()["error"], "offset_mismatch")
        self._upload(name, half, archive[half:])
        bad = self._post("drill/restore", json={"name": name, "sha256": "0" * 64})
        self._assert_error(bad, 422, "sha256_mismatch")
        resp = self._post("drill/restore", json={"name": name, "sha256": hashlib.sha256(archive).hexdigest()})
        self.assertEqual(resp.status_code, 202, resp.text[:300])
        deadline = time.time() + 240
        while True:
            ds = self._post("drill/status", json={"name": name}).json()
            if ds["state"] in ("done", "failed") or time.time() > deadline:
                break
            time.sleep(0.5)
        self.assertEqual(ds["state"], "done", ds)
        self.assertEqual(ds["neutralization"]["active_crons"], 0)
        self.assertEqual(ds["neutralization"]["active_mail_servers"], 0)
        self.assertTrue(ds["neutralization"]["is_neutralized_flag"])
        self.assertEqual(ds["neutralization"]["pairing_left"], 0)
        with closing(psycopg2.connect(dbname=name, **self._pg_kwargs())) as cnx, cnx.cursor() as cr:
            cr.execute("SELECT count(*) FROM ir_cron c WHERE active AND id NOT IN (SELECT res_id FROM ir_model_data "
                       "WHERE model='ir.cron' AND module='base' AND name='autovacuum_job')")
            self.assertEqual(cr.fetchone()[0], 0)
            cr.execute("SELECT value FROM ir_config_parameter WHERE key='database.uuid'")
            drill_uuid = cr.fetchone()[0]
        live_uuid = self.env["ir.config_parameter"].sudo().get_str("database.uuid")
        self.assertNotEqual(drill_uuid, live_uuid)
        self.env.invalidate_all()
        rec = self.env["salvor.connector.drill"].search([("name", "=", name)])
        self.assertEqual(rec.state, "restored")
        resp = self._post("drop", json={"name": name})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(self._drill_db_exists(name))
        self.env.invalidate_all()
        self.assertEqual(rec.state, "dropped")
        # dropped is final: a second drop is refused like an unknown name
        self._assert_error(self._post("drop", json={"name": name}), 404, "db_not_found")

    def test_drill_v1_restore_owned_and_neutralized(self):
        self.cfg.drill_enabled = True
        archive = self._post("backup", json={"format": "dump"}).content
        name = drill_name("ut_v1")
        self._force_drop(name)
        self.addCleanup(self._force_drop, name)
        resp = self.opener.post(self.base_url() + "/salvor/v1/restore",
                                headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN},
                                data={"name": name}, files={"backup_file": ("x.dump", archive)}, timeout=300)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.env.invalidate_all()
        self.assertEqual(self.env["salvor.connector.drill"].search([("name", "=", name)]).state, "restored")
        self.assertEqual(self._post("drop", json={"name": name}).status_code, 200)
        self.assertFalse(self._drill_db_exists(name))

    def test_drill_disk_precheck(self):
        self.cfg.drill_enabled = True
        with patch.object(tools, "disk_free", return_value=2 * 1024 ** 3):
            resp = self._post("drill/start", json={"name": drill_name("ut_disk"), "size": 1024 ** 3})
            self._assert_error(resp, 507, "insufficient_disk")
        self.assertFalse(self._drill_db_exists(drill_name("ut_disk")))

    # --- scope proof ----------------------------------------------------------
    def test_scope_foreign_and_non_drill_dbs(self):
        """The backup token can't create/restore/drop anything but its OWN drills."""
        self.cfg.drill_enabled = True
        foreign = drill_name("ut_foreign")  # e.g. another paired database's drill
        if not dbcompat.pg_db_exists(foreign):
            subprocess.run([find_pg_tool("createdb"), foreign], env=exec_pg_environ(), check=True)
        self.addCleanup(self._force_drop, foreign)
        self._assert_error(self._post("drop", json={"name": foreign}), 404, "db_not_found")
        self._assert_error(self._post("drill/status", json={"name": foreign}), 404, "db_not_found")
        self._assert_error(self._upload(foreign, 0, b"x", expect=404), 404, "db_not_found")
        self._assert_error(self._post("drill/restore", json={"name": foreign, "sha256": "0" * 64}),
                           404, "db_not_found")
        # claiming an existing name is a conflict: it never becomes ours
        self._assert_error(self._post("drill/start", json={"name": foreign, "size": 10}), 409, "drill_exists")
        self._assert_error(self._post("drop", json={"name": foreign}), 404, "db_not_found")
        self.assertTrue(dbcompat.pg_db_exists(foreign))
        # non-drill names: the live db, system dbs, anything else
        for bad in (self.dbname, "postgres", "template1", "prod", "salvor_drill_A"):
            self._assert_error(self._post("drop", json={"name": bad}), 422, "bad_args")
            self._assert_error(self._post("drill/start", json={"name": bad, "size": 10}), 422, "bad_args")
            resp = self.opener.post(self.base_url() + "/salvor/v1/restore",
                                    headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN},
                                    data={"name": bad}, files={"backup_file": ("x.dump", b"PGDMP")})
            self._assert_error(resp, 422, "bad_args")
        # there is no listing endpoint, and info names only this database
        for path in ("list", "db/list", "databases"):
            resp = self._post(path)
            self.assertEqual(resp.status_code, 404)
        info = self._post("info").json()
        self.assertNotIn(foreign, str(info))

    def test_revoked_and_wrong_db_token(self):
        self.cfg.action_disconnect()
        for ep in ("info", "backup/start", "backup/status", "drill/start", "drop"):
            self._assert_error(self._post(ep, json={}), 401, "unauthorized")
        self.cfg.token_hash = sha256_hex("another-db-token-" + "x" * 40)
        for ep in ("info", "backup/start", "drop"):
            self._assert_error(self._post(ep, json={}), 401, "unauthorized")

    def test_log_retention_and_rotate(self):
        log = self.env["salvor.connector.log"]
        old = log.sudo().create({"endpoint": "info", "http_status": 200, "result": "ok",
                                 "date": "2020-01-01 00:00:00"})
        new = log.sudo().create({"endpoint": "info", "http_status": 200, "result": "ok"})
        self.env["salvor.connector.config"]._cron_housekeeping()
        self.assertFalse(old.exists())
        self.assertTrue(new.exists())
        with self.assertRaises(UserError):
            self.cfg.action_rotate()
        self.assertEqual(self.cfg.token_hash, sha256_hex(TOKEN))  # rotation without a code changes nothing

    # --- helpers ----------------------------------------------------------------
    def _upload(self, name, offset, data, expect=200):
        resp = self.opener.post(self.base_url() + "/salvor/v1/drill/upload", data=data, timeout=120, headers={
            "X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN,
            "X-Salvor-Drill": name, "X-Salvor-Offset": str(offset),
            "Content-Type": "application/octet-stream"})
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return resp

    @staticmethod
    def _pg_kwargs():
        env = exec_pg_environ()
        out = {}
        for key, arg in (("PGHOST", "host"), ("PGPORT", "port"), ("PGUSER", "user"), ("PGPASSWORD", "password")):
            if env.get(key):
                out[arg] = env[key]
        return out

    def test_neutralize_unpairs_copy(self):
        from odoo.modules.neutralize import neutralize_database
        self.cfg.drill_enabled = True
        self.env.flush_all()
        neutralize_database(self.env.cr)
        self.env.invalidate_all()
        self.assertFalse(self.cfg.token_hash)
        self.assertFalse(self.cfg.enabled)
        self.assertFalse(self.cfg.allowed_ips)
        self._assert_error(self._post("info"), 401, "unauthorized")

    def test_refusal_rows_are_rate_limited(self):
        from ..controllers import main as ctl
        log = self.env["salvor.connector.log"]
        for _i in range(ctl.REFUSALS_PER_MINUTE + 15):
            self._post("info", token="nope")
        self.env.invalidate_all()
        self.assertLessEqual(log.search_count([("http_status", "=", 401)]), ctl.REFUSALS_PER_MINUTE)

    def test_disconnect_stops_and_wipes_jobs(self):
        job_id, st = self._run_job("dump")
        path = tools.job_dir(self.dbname, job_id)
        self.assertTrue(os.path.isdir(path))
        self.cfg.action_disconnect()
        self.assertFalse(os.path.isdir(path))

    def test_drill_ownership_is_by_oid_not_name(self):
        """A drill name freed outside the connector and re-created by someone else
        (e.g. another paired db) is not ours any more: drop refuses it."""
        self.cfg.drill_enabled = True
        name = drill_name("ut_oid")
        self.addCleanup(self._force_drop, name)
        self.assertEqual(self._post("drill/start", json={"name": name, "size": 10}).status_code, 201)
        dbcompat.drop_drill(name)  # removed outside the connector
        subprocess.run([find_pg_tool("createdb"), name], env=exec_pg_environ(), check=True)  # someone else's
        self._assert_error(self._post("drop", json={"name": name}), 404, "db_not_found")
        self.assertTrue(dbcompat.pg_db_exists(name))
        self.env.invalidate_all()
        rec = self.env["salvor.connector.drill"].search([("name", "=", name)])
        self.assertEqual(rec.state, "dropped")

    def test_uninstall_hook_scope(self):
        from .. import uninstall_hook
        other = DbLock("some_other_db_ws3")
        self.assertTrue(other.acquire())
        other.release()
        self.cfg.drill_enabled = True
        name = drill_name("ut_unin")
        self.addCleanup(self._force_drop, name)
        self.assertEqual(self._post("drill/start", json={"name": name, "size": 10}).status_code, 201)
        uninstall_hook(self.env)
        self.assertTrue(os.path.exists(other.path))  # other databases' locks untouched
        self.assertFalse(dbcompat.pg_db_exists(name))  # our drill dropped

    def test_terminate_never_signals_a_foreign_pid(self):
        proc = subprocess.Popen(["sleep", "30"], start_new_session=True)
        try:
            start = tools.proc_start_time(proc.pid)
            tools.terminate(proc.pid, timeout=1, pid_start=start + 1)  # recycled pid
            tools.terminate(proc.pid, timeout=1, pid_start=start)  # not a jobrunner
            self.assertIsNone(proc.poll())
        finally:
            proc.kill()
            proc.wait()
