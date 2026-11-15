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

    def _owned_drill(self, name):
        """A drill db as 2.0.0/2.0.1 left it: created by the connector, recorded with its oid."""
        self._force_drop(name)
        subprocess.run([find_pg_tool("createdb"), name], env=exec_pg_environ(), check=True)
        oid = tools.db_oid(name)
        self.env["salvor.connector.drill"].sudo().create({"name": name, "state": "restored", "pg_oid": oid})
        self.env.flush_all()
        return oid

    def test_drill_endpoints_disabled(self):
        """2.0.4: the restore code is gone; every drill route is a 410 stub that
        touches neither the disk nor PostgreSQL, with or without a token."""
        from .. import jobrunner
        self.assertFalse(hasattr(jobrunner, "run_restore") or hasattr(jobrunner, "PsqlGuard"))
        drills_root = os.path.join(tools.config["data_dir"], "salvor_connector", "drills", self.dbname)
        before = os.path.exists(drills_root)
        for enabled in (False, True):
            self.cfg.drill_enabled = enabled
            for ep, body in (("drill/start", {"name": "salvor_drill_a", "size": 10}),
                             ("drill/restore", {"name": "salvor_drill_a", "sha256": "0" * 64}),
                             ("drill/status", {"name": "salvor_drill_a"})):
                self._assert_error(self._post(ep, json=body), 410, "drills_removed")
                self._assert_error(self._post(ep, json=body, token=None), 410, "drills_removed")
            self._assert_error(self._upload("salvor_drill_a", 0, b"x", expect=410), 410, "drills_removed")
            self._assert_error(self._v1_restore("salvor_drill_a", b"PGDMP"), 410, "drills_removed")
        self.assertFalse(dbcompat.pg_db_exists("salvor_drill_a"))
        self.assertEqual(os.path.exists(drills_root), before)
        self.assertFalse(self.env["salvor.connector.drill"].search([("name", "=", "salvor_drill_a")]))
        info = self._post("info").json()
        self.assertFalse(info["drill_enabled"])
        self.assertNotIn("upload_chunk_max", info)
        self.assertFalse([c for c in info["capabilities"] if c.startswith("drill_") and c != "drill_cleanup"])
        self.cfg._force_drills_off()
        self.assertFalse(self.cfg.drill_enabled)
        # the disabled upload route rejects a body before Odoo parses it
        resp = self.opener.post(self.base_url() + "/salvor/v1/drill/upload", data=b"x" * 4096, timeout=60,
                                headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN,
                                         "X-Salvor-Drill": "salvor_drill_a", "X-Salvor-Offset": "0",
                                         "Content-Type": "application/octet-stream"})
        self.assertEqual(resp.status_code, 413, resp.text[:200])

    def test_drop_leftovers_needs_admin(self):
        user = self.env["res.users"].create({"name": "salvor ut user", "login": "salvor_ut_user_%s" % RUN,
                                             "group_ids" if "group_ids" in self.env["res.users"]._fields
                                             else "groups_id": [(6, 0, [self.env.ref("base.group_user").id])]})
        name = drill_name("ut_adm")
        self.addCleanup(self._force_drop, name)
        self._owned_drill(name)
        with self.assertRaises(UserError):  # AccessError is a UserError too
            self.cfg.with_user(user).action_drop_drills()
        self.assertTrue(dbcompat.pg_db_exists(name))
        self.cfg.action_drop_drills()  # administrator
        self.assertFalse(dbcompat.pg_db_exists(name))
        self.env.invalidate_all()
        self.assertEqual(self.cfg.leftover_drill_count, 0)

    def test_bad_drill_name(self):
        self._assert_error(self._post("drop", json={"name": "salvor_drill_x"}), 404, "db_not_found")
        for bad in ("prod", self.dbname, "salvor_drill_", "salvor_drill_X", "salvor_drill_a;drop",
                    "salvor_drill_../a", "salvor_drill_" + "a" * 41):
            self._assert_error(self._post("drop", json={"name": bad}), 422, "bad_args")

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

    def _v1_restore(self, name, archive):
        return self.opener.post(self.base_url() + "/salvor/v1/restore",
                                headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN},
                                data={"name": name}, files={"backup_file": ("x.dump", archive)}, timeout=60)

    # --- scope proof ----------------------------------------------------------
    def test_scope_foreign_and_non_drill_dbs(self):
        """drop removes only drill dbs THIS database's connector created."""
        foreign = drill_name("ut_foreign")  # e.g. another paired database's drill
        if not dbcompat.pg_db_exists(foreign):
            subprocess.run([find_pg_tool("createdb"), foreign], env=exec_pg_environ(), check=True)
        self.addCleanup(self._force_drop, foreign)
        self._assert_error(self._post("drop", json={"name": foreign}), 404, "db_not_found")
        self.assertTrue(dbcompat.pg_db_exists(foreign))
        for bad in (self.dbname, "postgres", "template1", "prod", "salvor_drill_A"):
            self._assert_error(self._post("drop", json={"name": bad}), 422, "bad_args")
        own = drill_name("ut_own")
        self.addCleanup(self._force_drop, own)
        self._owned_drill(own)
        self.assertEqual(self._post("drop", json={"name": own}).status_code, 200)
        self.assertFalse(dbcompat.pg_db_exists(own))
        for path in ("list", "db/list", "databases"):
            self.assertEqual(self._post(path).status_code, 404)
        self.assertNotIn(foreign, str(self._post("info").json()))

    def test_revoked_and_wrong_db_token(self):
        self.cfg.action_disconnect()
        for ep in ("info", "backup/start", "backup/status", "drop"):
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
        self._owned_drill(name)
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
        self._owned_drill(name)
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

    def test_drill_drop_button_and_stale_gc(self):
        self.cfg.drill_enabled = True
        name = drill_name("ut_btn")
        self._force_drop(name)
        self.addCleanup(self._force_drop, name)
        self._owned_drill(name)
        self.env.invalidate_all()
        rec = self.env["salvor.connector.drill"].search([("name", "=", name)])
        rec.state = "restoring"  # a restore left running by 2.0.0/2.0.1 counts as unfinished
        self.env["salvor.connector.drill"]._gc_stale()  # fresh: kept
        self.assertTrue(self._drill_db_exists(name))
        self.env.cr.execute("UPDATE salvor_connector_drill SET create_date = (now() at time zone 'UTC') - interval '7 hours' "
                            "WHERE id = %s", (rec.id,))
        self.env.invalidate_all()
        self.env["salvor.connector.drill"]._gc_stale()
        self.assertFalse(self._drill_db_exists(name))
        self.assertEqual(rec.state, "dropped")
        # the button, and Disconnect, drop what is left
        name2 = drill_name("ut_dis")
        self.addCleanup(self._force_drop, name2)
        self._owned_drill(name2)
        self.env.invalidate_all()
        self.cfg.action_disconnect()
        self.assertFalse(self._drill_db_exists(name2))
        self.assertFalse(self.cfg.allowed_ips)
        self.assertFalse(self.cfg.drill_enabled)
        self.assertFalse(os.path.isdir(os.path.dirname(tools.drill_dir(self.dbname, name2))))

    def test_backup_jobs_are_capped(self):
        ids = [self._run_job("dump")[0] for _ in range(3)]
        self.assertEqual(sorted(os.listdir(tools.jobs_root(self.dbname))), sorted(ids[1:]))

    def test_pull_log_cap_evicts_refusals_first(self):
        from ..models import salvor_connector_log as logmod
        log = self.env["salvor.connector.log"].sudo()
        log.search([]).unlink()
        log.create([{"endpoint": "info", "http_status": 200} for _ in range(3)])
        log.create([{"endpoint": "info", "http_status": 401} for _ in range(5)])
        with patch.object(logmod, "MAX_ROWS", 4):
            log._gc_old_rows()
        self.assertEqual(sorted(log.search([]).mapped("http_status")), [200, 200, 200, 401])
