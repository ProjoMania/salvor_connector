import hashlib
import io
import os
import shutil
import subprocess
import tempfile
import zipfile

from odoo.tests import HttpCase, tagged
from odoo.tools.misc import exec_pg_environ, find_pg_tool

from ..tools import DbLock, sha256_hex

TOKEN = "t" * 20 + "0123456789abcdefghijklmnopqrstuv"


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

    def _post(self, endpoint, json=None, token=TOKEN, db=None, stream=False, **kw):
        headers = {"X-Salvor-Db": db or self.dbname}
        if token:
            headers["Authorization"] = "Bearer " + token
        return self.opener.post(self.base_url() + "/salvor/v1/" + endpoint, json=json if json is not None else {},
                                headers=headers, stream=stream, timeout=120, **kw)

    def _assert_error(self, resp, status, code):
        self.assertEqual(resp.status_code, status, resp.text[:300])
        self.assertEqual(resp.json()["error"], code)

    # --- refusals ---------------------------------------------------------
    def test_missing_and_wrong_token(self):
        self._assert_error(self._post("info", token=None), 401, "bad_token")
        self._assert_error(self._post("info", token="nope"), 401, "bad_token")
        self._assert_error(self._post("info", token=TOKEN + "x"), 401, "bad_token")

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
        self._assert_error(self._post("info"), 401, "not_paired")

    def test_disabled(self):
        self.cfg.enabled = False
        self._assert_error(self._post("info"), 403, "disabled")

    def test_unknown_db(self):
        self._assert_error(self._post("info", db="no_such_db_salvor_x"), 404, "db_not_found")
        self._assert_error(self._post("info", db="../etc/passwd"), 404, "db_not_found")
        self._assert_error(self._post("info", db="-h"), 404, "db_not_found")

    def test_bad_drill_name(self):
        self._assert_error(self._post("drop", json={"name": "salvor_drill_x"}), 404, "db_not_found")
        for bad in ("prod", self.dbname, "salvor_drill_", "salvor_drill_X", "salvor_drill_a;drop",
                    "salvor_drill_../a", "salvor_drill_" + "a" * 41):
            self._assert_error(self._post("drop", json={"name": bad}), 422, "bad_args")
        # restore refused while drills are disabled (default)
        resp = self.opener.post(self.base_url() + "/salvor/v1/restore",
                                headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN},
                                data={"name": "salvor_drill_a"}, files={"file": ("x.dump", b"PGDMP")})
        self._assert_error(resp, 403, "drill_disabled")
        self.cfg.drill_enabled = True
        resp = self.opener.post(self.base_url() + "/salvor/v1/restore",
                                headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN},
                                data={"name": self.dbname}, files={"file": ("x.dump", b"PGDMP")})
        self._assert_error(resp, 422, "bad_args")

    def test_bad_format(self):
        self._assert_error(self._post("backup", json={"format": "tar"}), 422, "bad_args")

    # --- happy paths ------------------------------------------------------
    def test_info(self):
        resp = self._post("info")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        data = resp.json()
        self.assertEqual(data["protocol"], 1)
        self.assertEqual(data["db"], self.dbname)
        self.assertFalse(data["drill_enabled"])
        self.assertGreater(data["db_size_bytes"], 0)
        for key in ("module_version", "odoo_version", "filestore_bytes_estimate"):
            self.assertIn(key, data)
        self.assertTrue(self.env["ir.logging"].search_count(
            [("name", "=", "salvor_connector"), ("func", "=", "info")]))
        logged = self.env["ir.logging"].search([("name", "=", "salvor_connector")]).mapped("message")
        self.assertFalse(any(TOKEN in m or sha256_hex(TOKEN) in m for m in logged))

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
