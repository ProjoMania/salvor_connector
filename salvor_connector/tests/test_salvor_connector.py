import hashlib
import io
import os

import requests
import subprocess
import tempfile
import time
import zipfile
from contextlib import closing
from unittest.mock import patch

import psycopg2

from odoo.exceptions import UserError
from odoo.tests import HttpCase, tagged
from odoo.tools import config
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

    def test_wrong_ip_reports_the_address_seen(self):
        self.cfg.allowed_ips = "10.9.9.9"
        resp = self._post("info")
        self._assert_error(resp, 403, "ip_forbidden")
        body = resp.json()
        self.assertIn(body["remote_addr"], ("127.0.0.1", "::1"))
        self.assertFalse(body["cloudflare"])
        self.assertNotIn("10.9.9.9", resp.text)  # the allowlist itself is never echoed

    def test_cloudflare_client_address(self):
        cf, salvor = "162.158.86.137", "203.0.113.7"
        # CF edge as the resolved address (proxy_mode + XFF) or as the socket peer
        self.assertEqual(tools.client_address("127.0.0.1", cf, salvor), (salvor, True))
        self.assertEqual(tools.client_address(cf, cf, salvor), (salvor, True))
        self.assertEqual(tools.client_address("2606:4700::1", "2606:4700::1", salvor), (salvor, True))
        # a forged header from anywhere else is ignored
        self.assertEqual(tools.client_address("198.51.100.9", "198.51.100.9", salvor), ("198.51.100.9", False))
        self.assertEqual(tools.client_address("127.0.0.1", "198.51.100.9", salvor), ("198.51.100.9", False))
        # no header / junk header: unchanged behaviour
        self.assertEqual(tools.client_address("127.0.0.1", cf, None), (cf, False))
        self.assertEqual(tools.client_address("127.0.0.1", cf, "not-an-ip"), (cf, False))
        self.assertTrue(tools.is_cloudflare("::ffff:" + cf))

    def test_cloudflare_header_through_http(self):
        cf, salvor = "162.158.86.137", "203.0.113.7"
        self.cfg.allowed_ips = salvor
        with patch.dict(config.options, proxy_mode=True):
            # Cloudflare -> nginx -> Odoo: XFF ends with the CF edge, CF-Connecting-IP is Salvor
            ok = self._post("info", headers_extra={"X-Forwarded-For": cf, "CF-Connecting-IP": salvor})
            self.assertEqual(ok.status_code, 200, ok.text[:300])
            # straight to the origin with a forged header: refused, and the address seen is reported
            forged = self._post("info", headers_extra={"X-Forwarded-For": "198.51.100.9",
                                                       "CF-Connecting-IP": salvor})
            self._assert_error(forged, 403, "ip_forbidden")
            self.assertEqual(forged.json()["remote_addr"], "198.51.100.9")
            # behind Cloudflare without the header: Odoo sees the edge and says so
            edge = self._post("info", headers_extra={"X-Forwarded-For": cf})
            self._assert_error(edge, 403, "ip_forbidden")
            self.assertEqual(edge.json()["remote_addr"], cf)
            self.assertTrue(edge.json()["cloudflare"])
        # without proxy_mode the socket peer (127.0.0.1) is used and the header ignored
        self._assert_error(self._post("info", headers_extra={"CF-Connecting-IP": salvor}), 403, "ip_forbidden")

    # --- pairing ---------------------------------------------------------
    def _fake_salvor(self, pair_status=200, pair_body=None, check_status=200, check_body=None):
        calls = []

        class Resp:
            def __init__(self, status, body):
                self.status_code, self._body = status, body

            def json(self):
                if self._body is None:
                    raise ValueError("no json")
                return self._body

        def post(url, json=None, headers=None, **kw):
            calls.append((url, json, headers))
            if url.endswith("/api/connector/pair"):
                return Resp(pair_status, pair_body if pair_body is not None else {
                    "token": "n" * 43, "salvor_ips": ["203.0.113.7"], "instance_id": 42})
            return Resp(check_status, check_body)
        return calls, patch("odoo.addons.salvor_connector.models.salvor_connector_config.requests.post", post)

    def test_pair_refusal_shows_salvor_detail(self):
        self.cfg.pairing_code = "SLV-ABCD-EFGH"
        detail = "odoo_url: Odoo must be reachable over https:// — set web.base.url to the https address"
        calls, p = self._fake_salvor(pair_status=422, pair_body={"detail": detail})
        with p, self.assertRaises(UserError) as cm:
            self.cfg.action_connect()
        self.assertIn("HTTP 422", str(cm.exception))
        self.assertIn("reachable over https://", str(cm.exception))
        calls, p = self._fake_salvor(pair_status=422, pair_body={"detail": [{"msg": "field required"}]})
        with p, self.assertRaises(UserError) as cm:
            self.cfg.action_connect()
        self.assertIn("field required", str(cm.exception))

    def test_pair_then_reachability_check(self):
        self.cfg.pairing_code = "SLV-ABCD-EFGH"
        calls, p = self._fake_salvor(check_body={"ok": True, "detail": "Salvor reached this database."})
        with p:
            self.assertIs(self.cfg.action_connect(), True)
        self.assertEqual(self.cfg.check_state, "ok")
        url, body, headers = calls[1]
        self.assertTrue(url.endswith("/api/connector/pair/check"))
        self.assertEqual(headers["Authorization"], "Bearer " + "n" * 43)
        self.assertEqual(body, {"db": self.dbname, "instance_id": "42"})
        self.assertEqual(self.cfg.token_hash, sha256_hex("n" * 43))

        self.cfg.pairing_code = "SLV-ABCD-EFGH"
        msg = "Odoo saw address 162.158.86.137 (a Cloudflare address) ..."
        calls, p = self._fake_salvor(check_body={"ok": False, "detail": msg})
        with p:
            action = self.cfg.action_connect()
        self.assertEqual(action["tag"], "display_notification")
        self.assertEqual(action["params"]["message"], msg)
        self.assertEqual(self.cfg.check_state, "failed")
        self.assertTrue(self.cfg.token_hash)  # still paired: the token is valid, the path is not

        self.cfg.pairing_code = "SLV-ABCD-EFGH"
        calls, p = self._fake_salvor(check_status=404, check_body={"detail": "Not Found"})
        with p:
            self.assertIs(self.cfg.action_connect(), True)
        self.assertEqual(self.cfg.check_state, "unknown")
        self.cfg.action_disconnect()
        self.assertFalse(self.cfg.check_state)

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
        touches neither the disk nor PostgreSQL. 2.0.5: the stubs check token, IP
        and enabled first (same 401/403 as any route, logged) and refuse bodies
        over 1 KiB."""
        from .. import jobrunner
        self.assertFalse(hasattr(jobrunner, "run_restore") or hasattr(jobrunner, "PsqlGuard"))
        self.assertFalse(self.cfg.drill_enabled)  # kept only for pre-upgrade views; always off
        log = self.env["salvor.connector.log"].sudo()
        drills_root = os.path.join(tools.config["data_dir"], "salvor_connector", "drills", self.dbname)
        before = os.path.exists(drills_root)
        stubs = (("drill/start", {"name": "salvor_drill_a", "size": 10}),
                 ("drill/restore", {"name": "salvor_drill_a", "sha256": "0" * 64}),
                 ("drill/status", {"name": "salvor_drill_a"}),
                 ("drill/upload", {}), ("restore", {}))
        for ep, body in stubs:
            self._assert_error(self._post(ep, json=body), 410, "drills_removed")
            self._assert_error(self._post(ep, json=body, token=None), 401, "unauthorized")
            self._assert_error(self._post(ep, json=body, token="nope"), 401, "unauthorized")
        self._assert_error(self._upload("salvor_drill_a", 0, b"x", expect=410), 410, "drills_removed")
        self._assert_error(self._v1_restore("salvor_drill_a", b"PGDMP"), 410, "drills_removed")
        self.env.invalidate_all()
        for ep, _body in stubs:
            self.assertTrue(log.search_count([("endpoint", "=", ep), ("http_status", "=", 410)]), ep)
            self.assertTrue(log.search_count([("endpoint", "=", ep), ("http_status", "=", 401)]), ep)
        self.cfg.allowed_ips = "10.9.9.9"
        self._assert_error(self._post("drill/start", json={}), 403, "ip_forbidden")
        self.cfg.write({"allowed_ips": "127.0.0.1\n::1", "enabled": False})
        self._assert_error(self._post("restore", json={}), 403, "disabled")
        self.cfg.enabled = True
        self.assertFalse(dbcompat.pg_db_exists("salvor_drill_a"))
        self.assertEqual(os.path.exists(drills_root), before)
        self.assertFalse(self.env["salvor.connector.drill"].search([("name", "=", "salvor_drill_a")]))
        info = self._post("info").json()
        self.assertFalse(info["drill_enabled"])
        self.assertNotIn("upload_chunk_max", info)
        self.assertFalse([c for c in info["capabilities"] if c.startswith("drill_") and c != "drill_cleanup"])
        # every stub rejects a body over 1 KiB before Odoo parses it
        for ep, _body in stubs:
            resp = self.opener.post(self.base_url() + "/salvor/v1/" + ep, data=b"x" * 4096, timeout=60,
                                    headers={"X-Salvor-Db": self.dbname, "Authorization": "Bearer " + TOKEN,
                                             "Content-Type": "application/octet-stream"})
            self.assertEqual(resp.status_code, 413, "%s %s" % (ep, resp.text[:200]))

    SALVOR_ROUTES = ("info", "backup", "backup/start", "backup/status", "backup/download",
                     "backup/cleanup", "drop", "drill/start", "drill/upload", "drill/restore",
                     "drill/status", "restore")

    def _raw_post(self, path, headers, body):
        """Send one raw HTTP request; return the status code of the answer."""
        import contextlib
        from urllib.parse import urlsplit
        url = urlsplit(self.base_url())
        allow = getattr(self, "allow_requests", None)  # Odoo 19+: requests need the test cookie
        with (allow() if allow else contextlib.nullcontext()):
            return self._raw_send(url, path, headers, body)

    def _raw_send(self, url, path, headers, body):
        import socket
        lines = ["POST %s HTTP/1.1" % path, "Host: %s" % url.netloc, "Connection: close"]
        cookie = "; ".join("%s=%s" % (c.name, c.value) for c in self.opener.cookies)
        if cookie:
            lines.append("Cookie: " + cookie)
        lines += ["%s: %s" % kv for kv in headers.items()]
        with socket.create_connection((url.hostname, url.port), timeout=60) as sock:
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
            data = b""
            while b"\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            status = int(data.split(b" ", 2)[1])
        return status

    def test_chunked_bodies_refused_before_auth(self):
        """2.0.10/2.0.11: on every /salvor/ route a chunked body (Transfer-Encoding:
        chunked), with or without a Content-Length, gets 413 before it is parsed
        and before the token check. The body is small, so the server can answer
        without the upload being cut off: a connection error is a failure."""
        body = b"a=" + b"x" * 2046
        chunked = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
        self.assertEqual(len(self.SALVOR_ROUTES), 12)
        for ep in self.SALVOR_ROUTES:
            for token in (None, TOKEN):
                for with_length in (False, True):
                    headers = {"X-Salvor-Db": self.dbname, "Transfer-Encoding": "chunked",
                               "Content-Type": "application/x-www-form-urlencoded"}
                    if with_length:
                        headers["Content-Length"] = "10"
                    if token:
                        headers["Authorization"] = "Bearer " + token
                    status = self._raw_post("/salvor/v1/" + ep, headers, chunked)
                    self.assertEqual(status, 413, "%s token=%s content-length=%s" % (ep, bool(token), with_length))
        # normal requests are unaffected
        self.assertEqual(self._post("info").status_code, 200)
        self._assert_error(self._post("drill/start", json={}), 410, "drills_removed")

    def test_routes_not_served_without_a_database(self):
        """2.0.11: the routes are auth="public", which Odoo never puts on its
        no-database routing map (a server-wide --load would otherwise expose them)."""
        try:
            from odoo.http import _generate_routing_rules
        except ImportError:  # Odoo 20
            from odoo.http.routing_map import _generate_routing_rules
        nodb = [url for url, _endpoint in _generate_routing_rules(["salvor_connector"], nodb_only=True)]
        self.assertEqual([u for u in nodb if u.startswith("/salvor/")], [])
        routed = [url for url, _endpoint in _generate_routing_rules(["salvor_connector"], nodb_only=False)]
        self.assertEqual(sorted(u for u in routed if u.startswith("/salvor/")),
                         sorted("/salvor/v1/" + ep for ep in self.SALVOR_ROUTES))

    def test_uninstall_hook_matches_the_loader(self):
        """2.0.11: Odoo 16 calls uninstall_hook(cr, registry), 17+ uninstall_hook(env).
        Check the hook against the call this Odoo's module loader really makes."""
        import inspect
        import re
        from odoo.modules import loading
        from .. import uninstall_hook
        call = re.search(r"getattr\(py_module, uninstall_hook\)\(([^)]*)\)", inspect.getsource(loading))
        self.assertTrue(call, "loader call not found")
        nargs = len([a for a in call.group(1).split(",") if a.strip()])
        self.assertEqual(len(inspect.signature(uninstall_hook).parameters), nargs, call.group(0))

    def test_no_merge_conflict_markers(self):
        """2.0.8: a store page shipped with conflict markers (2.0.6/2.0.7 on 17.0, 18.0, 20.0)."""
        import re
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        marker = re.compile(r"^(<<<<<<<|=======|>>>>>>>)( |$)", re.M)
        hits = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fn in filenames:
                if fn.endswith((".py", ".xml", ".html", ".csv", ".sql", ".md", ".txt", ".js", ".css")):
                    path = os.path.join(dirpath, fn)
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        if marker.search(fh.read()):
                            hits.append(os.path.relpath(path, root))
        self.assertEqual(hits, [])

    def test_big_bodies_refused_before_auth(self):
        """2.0.6: every working route refuses a body over 64 KiB (form or multipart
        included) with 413 before Odoo parses it, with or without a token."""
        big = b"x" * (128 * 1024)
        for ep in ("info", "backup", "backup/start", "backup/status", "backup/download",
                   "backup/cleanup", "drop"):
            for token in (None, TOKEN):
                headers = {"X-Salvor-Db": self.dbname}
                if token:
                    headers["Authorization"] = "Bearer " + token
                resp = self.opener.post(self.base_url() + "/salvor/v1/" + ep, headers=headers, timeout=60,
                                        files={"f": ("a.bin", big)})
                self.assertEqual(resp.status_code, 413, "%s %s" % (ep, resp.text[:200]))
                resp = self.opener.post(self.base_url() + "/salvor/v1/" + ep, headers=headers, timeout=60,
                                        data={"f": big.decode()})
                self.assertEqual(resp.status_code, 413, "%s form %s" % (ep, resp.text[:200]))
        # a normal JSON call still works
        self.assertEqual(self._post("info").status_code, 200)

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
        from .. import _uninstall_cleanup
        other = DbLock("some_other_db_ws3")
        self.assertTrue(other.acquire())
        other.release()
        name = drill_name("ut_unin")
        self.addCleanup(self._force_drop, name)
        self._owned_drill(name)
        _uninstall_cleanup(self.env)
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
