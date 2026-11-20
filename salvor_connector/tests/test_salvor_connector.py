import hashlib
import io
import os

import requests
import subprocess
import tempfile
import time
import zipfile
from contextlib import closing, contextmanager
from datetime import timedelta
from unittest.mock import patch

import psycopg2

from odoo import fields
from odoo.exceptions import UserError
from odoo.tests import HttpCase, tagged
from odoo.tools import config
from odoo.tools.misc import exec_pg_environ, find_pg_tool

from .. import dbcompat
from .. import tools
from ..tools import DbLock, sha256_hex

TOKEN = "t" * 20 + "0123456789abcdefghijklmnopqrstuv"
NEXT_TEST = "Choose Test connection in Salvor, or run a backup from Salvor."
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

    def _set_param(self, key, value):
        """Set a system parameter, or remove it (empty value); Odoo 20 renamed the setter."""
        icp = self.env["ir.config_parameter"].sudo()
        if value:
            (icp.set_str if hasattr(icp, "set_str") else icp.set_param)(key, value)
        else:
            icp.search([("key", "=", key)]).unlink()

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
        # the whole contract Salvor reads; nothing else is in the body
        self.assertEqual(sorted(body), ["cloudflare", "cloudflare_mode", "error", "message",
                                        "remote_addr", "via_cloudflare"])
        self.assertIn(body["remote_addr"], ("127.0.0.1", "::1"))
        self.assertIs(body["cloudflare"], False)
        self.assertIs(body["via_cloudflare"], False)
        self.assertIs(body["cloudflare_mode"], False)  # "Odoo is behind Cloudflare" is off by default
        self.assertNotIn("10.9.9.9", resp.text)  # the allowlist itself is never echoed
        self.cfg.trust_cloudflare = True
        self.assertIs(self._post("info").json()["cloudflare_mode"], True)

    def test_cloudflare_client_address(self):
        """Every branch of the decision in tools.client_address."""
        cf, cf6, salvor, other = "162.158.86.137", "2606:4700::1", "203.0.113.7", "198.51.100.9"
        addr = tools.client_address
        # switch off (the default): the header is ignored, whoever sends it
        for peer, resolved in ((cf, cf), ("127.0.0.1", cf), (cf6, cf6), (other, other)):
            self.assertEqual(addr(peer, resolved, salvor), (resolved, False))
            self.assertEqual(addr(peer, resolved, salvor, trust_cloudflare=False), (resolved, False))
        on = {"trust_cloudflare": True}
        # switch on: honoured from a Cloudflare address (the socket peer, or the one resolved
        # through proxy_mode + X-Forwarded-For)
        self.assertEqual(addr("127.0.0.1", cf, salvor, **on), (salvor, True))
        self.assertEqual(addr(cf, cf, salvor, **on), (salvor, True))
        self.assertEqual(addr(cf6, cf6, salvor, **on), (salvor, True))
        self.assertEqual(addr("::ffff:" + cf, "::ffff:" + cf, "::ffff:" + salvor, **on), (salvor, True))
        # ... never from any other address
        self.assertEqual(addr(other, other, salvor, **on), (other, False))
        self.assertEqual(addr("127.0.0.1", other, salvor, **on), (other, False))
        # ... not when Cloudflare marks the request as made by a Worker
        self.assertEqual(addr(cf, cf, salvor, cf_worker="evil.example", **on), (cf, False))
        self.assertEqual(addr("127.0.0.1", cf, salvor, cf_worker="", **on), (cf, False))
        # ... and not without exactly one valid address in the header
        for junk in (None, "", "not-an-ip", salvor + ", 6.6.6.6"):
            self.assertEqual(addr("127.0.0.1", cf, junk, **on), (cf, False))
        # an override list replaces the built-in one: only its networks count as Cloudflare
        nets, error = tools.cloudflare_nets("198.51.100.0/24, 2001:db8::/32")
        self.assertIsNone(error)
        self.assertEqual(addr(other, other, salvor, nets=nets, **on), (salvor, True))
        self.assertEqual(addr(cf, cf, salvor, nets=nets, **on), (cf, False))
        self.assertEqual(addr(other, other, salvor, nets=nets), (other, False))  # and still nothing while off
        self.assertTrue(tools.is_cloudflare("::ffff:" + cf))
        self.assertFalse(tools.is_cloudflare(cf, nets))

    def test_cloudflare_ranges_override_is_validated(self):
        builtin = tools._CLOUDFLARE_NETS
        self.assertEqual(len(builtin), 22)
        for empty in (None, False, "", "  ", ",\n"):
            self.assertEqual(tools.cloudflare_nets(empty), (builtin, None))
        nets, error = tools.cloudflare_nets("198.51.100.0/24,2001:db8::/32\n 203.0.113.9")
        self.assertIsNone(error)
        self.assertEqual([str(n) for n in nets], ["198.51.100.0/24", "2001:db8::/32", "203.0.113.9/32"])
        # one bad entry: the override is not used at all, the built-in list applies
        for bad in ("198.51.100.0/24, nonsense", "198.51.100.7/24", "0.0.0.0/0", "::/0", "10.0.0.0/7",
                    "2000::/3", "1.2.3.4/33"):
            nets, error = tools.cloudflare_nets(bad)
            self.assertEqual(nets, builtin, bad)
            self.assertTrue(error, bad)
        # ... and so does a local range: behind a proxy of your own every request comes from one,
        # and the header would be trusted from everybody
        for local in ("127.0.0.0/8", "127.0.0.1", "10.0.0.0/8", "10.1.2.0/24", "172.16.5.0/24", "192.168.1.0/24",
                      "169.254.0.0/16", "100.64.0.0/10", "::1", "fd12:3456::/32", "fe80::/64",
                      "198.51.100.0/24, 192.168.0.1"):
            nets, error = tools.cloudflare_nets(local)
            self.assertEqual(nets, builtin, local)
            self.assertIn("loopback, private or link-local", error, local)
        # the settings read the system parameter
        # an IPv4-mapped entry would never match (addresses are compared unwrapped): refused, not ignored
        for mapped in ("::ffff:198.51.100.0/120", "::ffff:203.0.113.9", "198.51.100.0/24, ::ffff:c633:6400/120"):
            nets, error = tools.cloudflare_nets(mapped)
            self.assertEqual(nets, builtin, mapped)
            self.assertIn("IPv4-mapped", error, mapped)
        # a list that long is a mistake, and it would be parsed in the request path
        many = ", ".join("198.51.%d.%d" % (i // 256, i % 256) for i in range(tools.CLOUDFLARE_RANGES_MAX + 1))
        nets, error = tools.cloudflare_nets(many)
        self.assertEqual(nets, builtin)
        self.assertIn("more than %d" % tools.CLOUDFLARE_RANGES_MAX, error)
        nets, error = tools.cloudflare_nets(many.rsplit(",", 1)[0])
        self.assertIsNone(error)
        self.assertEqual(len(nets), tools.CLOUDFLARE_RANGES_MAX)
        # the same text is parsed once per process
        with patch.object(tools, "parse_cloudflare_ranges", wraps=tools.parse_cloudflare_ranges) as parse:
            for _i in range(5):
                tools.cloudflare_nets("203.0.113.0/24, 2001:db8:77::/48")
            self.assertEqual(parse.call_count, 1)
        self._set_param(tools.CLOUDFLARE_RANGES_PARAM, "198.51.100.0/24")
        self.assertEqual([str(n) for n in self.cfg._cloudflare_nets()], ["198.51.100.0/24"])
        self._set_param(tools.CLOUDFLARE_RANGES_PARAM, "0.0.0.0/0")
        from ..models import salvor_connector_config as config_model
        config_model._warned_ranges.clear()  # the warning is logged once per value and process
        with self.assertLogs("odoo.addons.salvor_connector.models.salvor_connector_config", "WARNING"):
            self.assertEqual(self.cfg._cloudflare_nets(), builtin)
        self._set_param(tools.CLOUDFLARE_RANGES_PARAM, "")
        self.assertEqual(self.cfg._cloudflare_nets(), builtin)

    def _assert_refused(self, resp, **expected):
        self._assert_error(resp, 403, "ip_forbidden")
        body = resp.json()
        self.assertEqual({k: body[k] for k in expected}, expected, resp.text)

    def test_cloudflare_header_through_http(self):
        cf, salvor, other = "162.158.86.137", "203.0.113.7", "198.51.100.9"
        self.cfg.allowed_ips = salvor
        via_cf = {"X-Forwarded-For": cf, "CF-Connecting-IP": salvor}
        log = self.env["salvor.connector.log"].sudo()
        with patch.dict(config.options, proxy_mode=True):
            # switch off (the default, and what an upgrade from 2.0.12 leaves): Cloudflare -> nginx ->
            # Odoo with Salvor in CF-Connecting-IP is refused, and the body says the switch is off
            self.assertFalse(self.cfg.trust_cloudflare)
            self._assert_refused(self._post("info", headers_extra=via_cf),
                                 remote_addr=cf, cloudflare=True, via_cloudflare=False, cloudflare_mode=False)
            self.env.invalidate_all()
            row = log.search([("result", "=", "ip_forbidden")], limit=1)
            self.assertEqual(row.remote_addr, cf)
            self.assertIn("Odoo is behind Cloudflare", row.detail)
            # switch on: the same request is accepted, and the pull log shows the address that was checked
            self.cfg.trust_cloudflare = True
            ok = self._post("info", headers_extra=via_cf)
            self.assertEqual(ok.status_code, 200, ok.text[:300])
            self.env.invalidate_all()
            self.assertEqual(log.search([("http_status", "=", 200)], limit=1).remote_addr, salvor)
            # on, but Cloudflare marks the request as made by a Worker: the header is not used.
            # The pull log says why; the caller is told no more than before.
            refused = self._post("info", headers_extra=dict(via_cf, **{"CF-Worker": "evil.example"}))
            self._assert_refused(refused, remote_addr=cf, cloudflare=True, via_cloudflare=False, cloudflare_mode=True)
            self.assertEqual(sorted(refused.json()), ["cloudflare", "cloudflare_mode", "error", "message",
                                                      "remote_addr", "via_cloudflare"])
            self.assertNotIn("Worker", refused.text)
            self.env.invalidate_all()
            self.assertEqual(log.search([("result", "=", "ip_forbidden")], limit=1).detail,
                             "Source address not allowed (a Cloudflare address; CF-Worker header present)")
            for headers, why in (({"X-Forwarded-For": cf}, "no CF-Connecting-IP header"),
                                 ({"X-Forwarded-For": cf, "CF-Connecting-IP": "not-an-ip"},
                                  "CF-Connecting-IP is not one IP address")):
                self._assert_refused(self._post("info", headers_extra=headers), remote_addr=cf, cloudflare=True,
                                     via_cloudflare=False, cloudflare_mode=True)
                self.env.invalidate_all()
                self.assertEqual(log.search([("result", "=", "ip_forbidden")], limit=1).detail,
                                 "Source address not allowed (a Cloudflare address; %s)" % why)
            # on, not from a Cloudflare address: a forged header is ignored
            self._assert_refused(self._post("info", headers_extra={"X-Forwarded-For": other,
                                                                   "CF-Connecting-IP": salvor}),
                                 remote_addr=other, cloudflare=False, via_cloudflare=False, cloudflare_mode=True)
            # on, through Cloudflare, but the caller is not Salvor
            self._assert_refused(self._post("info", headers_extra={"X-Forwarded-For": cf,
                                                                   "CF-Connecting-IP": other}),
                                 remote_addr=other, cloudflare=False, via_cloudflare=True, cloudflare_mode=True)
            # on, a Cloudflare address without the header
            self._assert_refused(self._post("info", headers_extra={"X-Forwarded-For": cf}),
                                 remote_addr=cf, cloudflare=True, via_cloudflare=False, cloudflare_mode=True)
            # override list (system parameter): only its networks may present the header
            self._set_param(tools.CLOUDFLARE_RANGES_PARAM, "198.51.100.0/24")
            self._assert_refused(self._post("info", headers_extra=via_cf),
                                 remote_addr=cf, cloudflare=False, via_cloudflare=False, cloudflare_mode=True)
            ok = self._post("info", headers_extra={"X-Forwarded-For": other, "CF-Connecting-IP": salvor})
            self.assertEqual(ok.status_code, 200, ok.text[:300])
            # ... and with the switch off the override grants nothing either
            self.cfg.trust_cloudflare = False
            self._assert_refused(self._post("info", headers_extra={"X-Forwarded-For": other,
                                                                   "CF-Connecting-IP": salvor}),
                                 remote_addr=other, cloudflare=True, via_cloudflare=False, cloudflare_mode=False)
            self._set_param(tools.CLOUDFLARE_RANGES_PARAM, "")
            # a wrong token is refused before any of this is looked at: the same 401 whether the
            # address would pass (switch on, through Cloudflare) or not
            self.cfg.trust_cloudflare = True
            bodies = {self._post("info", token="nope", headers_extra=headers).text
                      for headers in (via_cf, {"X-Forwarded-For": other}, {"X-Forwarded-For": cf})}
            self.assertEqual(len(bodies), 1, bodies)
            self._assert_error(self._post("info", token="nope", headers_extra=via_cf), 401, "unauthorized")
            # ... and the ranges override is not even parsed before the token is right
            with patch.object(tools, "cloudflare_nets", side_effect=AssertionError("parsed before the token check")):
                self._assert_error(self._post("info", token="nope", headers_extra=via_cf), 401, "unauthorized")
                self._assert_error(self._post("info", token=None, headers_extra=via_cf), 401, "unauthorized")
            with patch.object(tools, "cloudflare_nets", wraps=tools.cloudflare_nets) as parse:
                self.assertEqual(self._post("info", headers_extra=via_cf).status_code, 200)
                self.assertTrue(parse.called)
        # without proxy_mode the socket peer (127.0.0.1) is what Odoo sees: the header is ignored
        self._assert_refused(self._post("info", headers_extra={"CF-Connecting-IP": salvor}),
                             cloudflare=False, via_cloudflare=False, cloudflare_mode=True)

    def test_calls_do_not_write_the_settings_row(self):
        """Calls from Salvor only add pull-log rows: a write on the settings row from
        another transaction is what broke a pairing or rotation in progress (2.0.12)."""
        self.env.flush_all()

        def row_version():
            self.env.cr.execute("SELECT ctid FROM salvor_connector_config WHERE id = %s", [self.cfg.id])
            return self.env.cr.fetchone()[0]
        before = row_version()
        self.assertEqual(self._post("info").status_code, 200)
        self._assert_error(self._post("info", token="nope"), 401, "unauthorized")
        self._assert_error(self._post("backup", json={"format": "tar"}), 422, "bad_args")
        self.assertEqual(row_version(), before)
        # "Last call" is read from the pull log
        self.env.invalidate_all()
        ok = self.env["salvor.connector.log"].sudo().search([("http_status", "<", 400)], limit=1)
        self.assertTrue(ok)
        self.assertEqual(self.cfg.last_call_at, ok.date)

    # --- pairing ---------------------------------------------------------
    def _fake_salvor(self, pair_status=200, pair_body=None, check_status=200, check_body=None, check=None,
                     pair=None):
        """Patch requests.post in the settings model. ``check`` (a callable) runs when the
        module asks for the connection test, before the answer; it may raise. ``pair`` runs
        while the module waits for the answer to /pair."""
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
                if pair is not None:
                    pair()
                return Resp(pair_status, pair_body if pair_body is not None else {
                    "token": "n" * 43, "salvor_ips": ["203.0.113.7"], "instance_id": 42})
            if check is not None:
                check()
            return Resp(check_status, check_body)
        return calls, patch("odoo.addons.salvor_connector.models.salvor_connector_config.requests.post", post)

    def _pair(self, **kw):
        self.cfg.pairing_code = "SLV-ABCD-EFGH"
        calls, p = self._fake_salvor(**kw)
        with p:
            return self.cfg.action_connect(), calls

    def test_pair_refusal_shows_salvor_detail(self):
        self.cfg.pairing_code = "SLV-ABCD-EFGH"
        self._set_param("web.base.url", "http://erp.example.com")
        detail = "odoo_url: Odoo must be reachable over https:// — set web.base.url to the https address"
        calls, p = self._fake_salvor(pair_status=422, pair_body={"detail": detail})
        with p, self.assertRaises(UserError) as cm:
            self.cfg.action_connect()
        message = str(cm.exception)
        # the code was not the problem: say what was, and with which setting of this database
        self.assertIn("Salvor did not complete the pairing (HTTP 422).", message)
        self.assertNotIn("refused the pairing code", message)
        self.assertNotIn("odoo_url", message)
        self.assertIn("http://erp.example.com (system parameter web.base.url)", message)
        self.assertIn("reachable over https://", message)
        self.assertEqual(self.cfg.pairing_code, "SLV-ABCD-EFGH")  # still there for the next click
        self.assertEqual(self.cfg.token_hash, sha256_hex(TOKEN))  # and nothing was changed
        calls, p = self._fake_salvor(pair_status=422, pair_body={"detail": [{"msg": "field required"}]})
        with p, self.assertRaises(UserError) as cm:
            self.cfg.action_connect()
        self.assertIn("field required", str(cm.exception))
        calls, p = self._fake_salvor(pair_status=400, pair_body={"detail": "Invalid or expired pairing code"})
        with p, self.assertRaises(UserError) as cm:
            self.cfg.action_connect()
        self.assertIn("(HTTP 400). Invalid or expired pairing code", str(cm.exception))

    def test_pair_then_reachability_check(self):
        result, calls = self._pair(check_body={"ok": True, "detail": "Salvor reached this database."})
        self.assertIs(result, True)
        self.assertEqual(self.cfg.check_state, "ok")
        self.assertEqual(self.cfg.connection_state, "ok")
        self.assertTrue(self.cfg.checked_at)
        url, body, headers = calls[1]
        self.assertTrue(url.endswith("/api/connector/pair/check"))
        self.assertEqual(headers["Authorization"], "Bearer " + "n" * 43)
        self.assertEqual(body, {"db": self.dbname, "instance_id": "42"})
        self.assertEqual(self.cfg.token_hash, sha256_hex("n" * 43))
        self.assertEqual(self.cfg.allowed_ips, "203.0.113.7")
        self.assertFalse(self.cfg.pairing_code)
        # a second click finds no code and never asks Salvor again
        calls, p = self._fake_salvor()
        with p, self.assertRaises(UserError):
            self.cfg.action_connect()
        self.assertEqual(calls, [])

        msg = "Odoo saw address 198.51.100.9, which is not an allowed Salvor address ..."
        action, calls = self._pair(check_body={"ok": False, "detail": msg, "code": "ip_forbidden"})
        self.assertEqual(action["tag"], "display_notification")
        self.assertEqual(action["params"]["message"], msg)
        self.assertEqual(self.cfg.check_state, "failed")
        self.assertEqual((self.cfg.connection_state, self.cfg.connection_message), ("failed", msg))
        self.assertFalse(self.cfg.offer_cloudflare)  # nothing here came from a Cloudflare address
        self.assertTrue(self.cfg.token_hash)  # still paired: the token is valid, the path is not

        result, calls = self._pair(check_status=404, check_body={"detail": "Not Found"})
        self.assertIs(result, True)
        self.assertEqual((self.cfg.check_state, self.cfg.connection_state), ("unknown", "unknown"))
        self.cfg.action_disconnect()
        self.assertFalse(self.cfg.check_state)
        self.assertFalse(self.cfg.connection_state)

    def test_reachability_timeout_is_not_a_failure(self):
        """Odoo not answering Salvor's test in time says nothing about the connection (a
        single-worker Odoo cannot answer while the button request runs): "not tested"."""
        detail = "Odoo did not answer Salvor within 20 s"
        result, calls = self._pair(check_body={"ok": False, "detail": detail, "code": "timeout"})
        self.assertIs(result, True)  # no "cannot reach" warning
        self.assertEqual((self.cfg.check_state, self.cfg.check_message), ("timeout", detail))
        self.assertEqual(self.cfg.connection_state, "timeout")
        self.assertTrue(self.cfg.token_hash)

        def too_slow():
            raise requests.ReadTimeout()
        result, calls = self._pair(check=too_slow)
        self.assertIs(result, True)
        self.assertEqual(self.cfg.check_state, "timeout")
        self.assertIn("ReadTimeout", self.cfg.check_message)

        # Salvor not reached at all (refused, or the connection itself timed out): no test was made
        for error in (requests.ConnectionError, requests.ConnectTimeout):
            def unreachable(error=error):
                raise error()
            result, calls = self._pair(check=unreachable)
            self.assertIs(result, True)
            self.assertEqual(self.cfg.check_state, "unknown", error)
            self.assertEqual(self.cfg.check_message,
                             "Could not ask Salvor to test the connection (%s). %s" % (error.__name__, NEXT_TEST))
            self.assertEqual(self.cfg.token_hash, sha256_hex("n" * 43))

    def test_reachability_answer_that_is_not_an_object(self):
        for body in (["not", "a", "dict"], "text", 7, None):
            result, calls = self._pair(check_body=body)
            self.assertIs(result, True, body)
            self.assertEqual(self.cfg.check_state, "unknown", body)
            self.assertEqual(self.cfg.check_message, "Unexpected answer from Salvor to the test request. " + NEXT_TEST)
            self.assertEqual(self.cfg.token_hash, sha256_hex("n" * 43))
        # every "not tested" result says how to test
        result, calls = self._pair(check_status=503, check_body={"detail": "busy"})
        self.assertEqual(self.cfg.check_message,
                         "Salvor could not run the connection test (HTTP 503). %s busy" % NEXT_TEST)
        result, calls = self._pair(check_status=404, check_body={"detail": "Not Found"})
        self.assertEqual(self.cfg.check_message,
                         "This Salvor does not test the connection at pairing; the first backup will.")

    def test_pair_answer_cannot_break_the_token_write(self):
        """Salvor has used the code once it answers: nothing in the rest of its answer may
        make the write of the new token fail."""
        result, calls = self._pair(
            pair_body={"token": "n" * 43, "instance_id": 42,
                       "salvor_ips": ["203.0.113.7", "not an ip", 7, None, " 10.0.0.0/8 ", "203.0.113.8 x",
                                      "203.0.113.9, bogus", "203.0.113.10\n203.0.113.11", ""]},
            check_body={"ok": True})
        self.assertIs(result, True)
        self.assertEqual(self.cfg.allowed_ips, "203.0.113.7\n10.0.0.0/8")
        self.assertEqual(self.cfg.check_message, "Salvor reached this database.")
        result, calls = self._pair(pair_body={"token": "m" * 43, "salvor_ips": "203.0.113.7"},
                                   check_body={"ok": True})
        self.assertEqual(self.cfg.token_hash, sha256_hex("m" * 43))
        self.assertFalse(self.cfg.allowed_ips)  # refuses everyone until the admin fills it
        for bad in (["token"], "x", {"token": "short"}, {"token": 7}, {}):
            self.cfg.pairing_code = "SLV-ABCD-EFGH"
            calls, p = self._fake_salvor(pair_body=bad)
            with p, self.assertRaises(UserError) as cm:
                self.cfg.action_connect()
            # Salvor may have used the code: say what to do next
            self.assertIn("The pairing is not complete: create a new pairing code in Salvor", str(cm.exception))
            self.assertEqual(self.cfg.token_hash, sha256_hex("m" * 43), bad)

    def test_later_call_replaces_a_stale_test_result(self):
        # a call that got through BEFORE the test says nothing about it
        self.assertEqual(self._post("info").status_code, 200)
        self.env.invalidate_all()
        self.env["salvor.connector.log"].sudo().search([]).write(
            {"date": fields.Datetime.now() - timedelta(hours=1)})
        action, calls = self._pair(check_body={"ok": False, "detail": "refused", "code": "ip_forbidden"})
        self.assertEqual(self.cfg.connection_state, "failed")
        # ... a call that gets through AFTER it does: the form stops saying "not reachable"
        self.cfg.write({"token_hash": sha256_hex(TOKEN), "allowed_ips": "127.0.0.1\n::1",
                        "checked_at": fields.Datetime.now() - timedelta(seconds=30)})
        self.assertEqual(self.cfg.connection_state, "failed")
        self.assertEqual(self._post("info").status_code, 200)
        self.env.invalidate_all()
        self.assertEqual(self.cfg.connection_state, "ok")
        self.assertEqual(self.cfg.connection_message, "Salvor has reached this database since the test.")
        self.assertEqual(self.cfg.check_state, "failed")  # the stored test result itself is kept
        # the same for a test that timed out
        self.cfg.check_state = "timeout"
        self.assertEqual(self.cfg.connection_state, "ok")
        self.cfg.checked_at = fields.Datetime.now() + timedelta(seconds=30)
        self.assertEqual(self.cfg.connection_state, "timeout")

    def test_pairing_offers_the_cloudflare_switch(self):
        """Salvor's test call arrives through Cloudflare while "Odoo is behind Cloudflare" is
        off: the module refuses it, says so, and offers the switch."""
        cf, salvor = "162.158.86.137", "203.0.113.7"
        via_cf = {"X-Forwarded-For": cf, "CF-Connecting-IP": salvor}
        seen = {}

        def salvor_calls_back():
            self.env.flush_all()
            with patch.dict(config.options, proxy_mode=True):
                seen["resp"] = self._post("info", token="n" * 43, headers_extra=via_cf)
            self.env.invalidate_all()
        salvor_text = "the Salvor Connector refused Salvor's address: Odoo saw the request come from %s" % cf
        # (Salvor's text names no address here: what counts is this database's own pull log)
        action, calls = self._pair(check=salvor_calls_back,
                                   check_body={"ok": False, "detail": "refused", "code": "ip_forbidden"})
        self._assert_refused(seen["resp"], remote_addr=cf, cloudflare=True, via_cloudflare=False,
                             cloudflare_mode=False)
        self.assertEqual(action["tag"], "display_notification")
        self.assertIn("Cloudflare address", action["params"]["message"])
        self.assertIn('"Odoo is behind Cloudflare" is switched off', action["params"]["message"])
        self.assertEqual(self.cfg.check_state, "failed")
        self.assertEqual(self.cfg.connection_state, "failed")  # the test's own refusal, not a later one
        self.assertEqual(self.cfg.check_message, "refused")
        self.assertTrue(self.cfg.check_cloudflare)
        self.assertTrue(self.cfg.offer_cloudflare)
        self.assertFalse(self.cfg.trust_cloudflare)  # offered, never switched on by the module itself
        # the offer is for administrators
        user = self.env["res.users"].create({"name": "salvor cf user", "login": "salvor_cf_user_%s" % RUN,
                                             "group_ids" if "group_ids" in self.env["res.users"]._fields
                                             else "groups_id": [(6, 0, [self.env.ref("base.group_user").id])]})
        with self.assertRaises(UserError):  # AccessError is a UserError too
            self.cfg.with_user(user).action_trust_cloudflare()
        self.assertFalse(self.cfg.trust_cloudflare)
        # the administrator takes it: the form no longer says "not reachable", it says "not tested"
        self.assertIs(self.cfg.action_trust_cloudflare(), True)
        self.assertTrue(self.cfg.trust_cloudflare)
        self.assertFalse(self.cfg.offer_cloudflare)
        self.assertEqual(self.cfg.connection_state, "unknown")
        self.assertTrue(self.cfg.connection_message.endswith("after the test. " + NEXT_TEST))
        # Salvor's next call, the same way, now gets through, and the form says so
        self.cfg.checked_at = fields.Datetime.now() - timedelta(seconds=30)
        with patch.dict(config.options, proxy_mode=True):
            self.assertEqual(self._post("info", token="n" * 43, headers_extra=via_cf).status_code, 200)
        self.env.invalidate_all()
        self.assertEqual(self.cfg.connection_state, "ok")
        # switched off again by hand: back to the refusal and the offer
        self.cfg.write({"trust_cloudflare": False, "checked_at": fields.Datetime.now() + timedelta(seconds=30)})
        self.assertEqual(self.cfg.connection_state, "failed")
        self.assertTrue(self.cfg.offer_cloudflare)
        # with the switch already on, a refusal from a Cloudflare address is not an offer
        self.cfg.trust_cloudflare = True
        action, calls = self._pair(check_body={"ok": False, "detail": "refused", "code": "ip_forbidden"})
        self.assertEqual(action["params"]["message"], "refused")
        self.assertFalse(self.cfg.check_cloudflare)
        self.assertEqual(self.cfg.connection_state, "failed")
        # no pull-log row for the refusal (at most 30 refusals a minute are kept): Salvor's text,
        # which repeats the address this database reported to it, is read instead
        self.cfg.trust_cloudflare = False
        self.env["salvor.connector.log"].sudo().search([]).unlink()
        refused = {"ok": False, "detail": salvor_text + " (a Cloudflare address).", "code": "ip_forbidden"}
        action, calls = self._pair(check_body=refused)
        self.assertTrue(self.cfg.offer_cloudflare)
        self.assertIn('"Odoo is behind Cloudflare" is switched off', action["params"]["message"])
        action, calls = self._pair(check_body=dict(refused, detail="Odoo saw the request come from 198.51.100.9."))
        self.assertFalse(self.cfg.offer_cloudflare)
        action, calls = self._pair(check_body=dict(refused, code=None))
        self.assertFalse(self.cfg.offer_cloudflare)

    def test_later_refusal_shows_on_the_form(self):
        """A call refused for its address after the test (and after every call that got through)
        replaces "Connected": e.g. a database paired through Cloudflare on 2.0.12, then upgraded."""
        cf, salvor = "162.158.86.137", "203.0.113.7"
        result, calls = self._pair(check_body={"ok": True})
        before = fields.Datetime.now() - timedelta(seconds=30)
        self.cfg.write({"token_hash": sha256_hex(TOKEN), "allowed_ips": "10.9.9.9", "checked_at": before,
                        "paired_at": before})
        self.assertEqual(self.cfg.connection_state, "ok")
        self._assert_error(self._post("info"), 403, "ip_forbidden")
        self.env.invalidate_all()
        self.assertEqual(self.cfg.connection_state, "refused")
        self.assertRegex(self.cfg.connection_message, r"it came from (127\.0\.0\.1|::1), which is not in Allowed IPs")
        self.assertFalse(self.cfg.offer_cloudflare)
        # from a Cloudflare address with the switch off: says so and points to the switch. No button:
        # that is offered for Salvor's own test at pairing only, and this row says what Odoo saw, not who called.
        self.cfg.allowed_ips = salvor
        with patch.dict(config.options, proxy_mode=True):
            self._assert_refused(self._post("info", headers_extra={"X-Forwarded-For": cf, "CF-Connecting-IP": salvor}),
                                 remote_addr=cf, cloudflare=True, cloudflare_mode=False)
        self.env.invalidate_all()
        self.assertEqual(self.cfg.connection_state, "refused")
        self.assertIn("it came from %s, a Cloudflare address" % cf, self.cfg.connection_message)
        self.assertIn('"Odoo is behind Cloudflare" is switched off', self.cfg.connection_message)
        self.assertFalse(self.cfg.offer_cloudflare)
        # the same for a pairing that was never tested (made before 2.0.12)
        self.cfg.write({"check_state": False, "check_message": False, "checked_at": False})
        self.assertEqual(self.cfg.connection_state, "refused")
        # with the switch on, the same call gets through, and the notice goes
        self.cfg.trust_cloudflare = True
        with patch.dict(config.options, proxy_mode=True):
            ok = self._post("info", headers_extra={"X-Forwarded-For": cf, "CF-Connecting-IP": salvor})
        self.assertEqual(ok.status_code, 200, ok.text[:300])
        self.env.invalidate_all()
        self.assertFalse(self.cfg.connection_state)
        self.cfg.write({"check_state": "ok", "checked_at": before})
        self.assertEqual(self.cfg.connection_state, "ok")
        # not paired: nothing is shown
        self.cfg.allowed_ips = "10.9.9.9"
        self._assert_error(self._post("info"), 403, "ip_forbidden")
        self.env.invalidate_all()
        self.assertEqual(self.cfg.connection_state, "refused")
        self.cfg.action_disconnect()
        self.assertFalse(self.cfg.connection_state)

    @contextmanager
    def _own_cursor_writes(self, failures=0, error=psycopg2.errors.SerializationFailure):
        """Send the settings writes of action_connect through the own-cursor retry loop, as outside
        tests, but on this test's cursor (a second connection could not see the test's data). The
        write that stores the token fails ``failures`` times first. Yields the attempts made."""
        Config = type(self.cfg)
        real_write = Config.write
        attempts = []

        def write(records, vals):
            if "token_hash" in vals:
                attempts.append(vals)
                if len(attempts) <= failures:
                    raise error()
            return real_write(records, vals)

        @contextmanager
        def same_cursor():
            yield self.env.cr
        module = "odoo.addons.salvor_connector.models.salvor_connector_config"
        with patch.object(Config, "_in_own_transaction", Config._retry_in_own_cursor), \
                patch.object(self.env.registry, "cursor", same_cursor), \
                patch.object(Config, "write", write), patch(module + ".time.sleep", lambda seconds: None):
            yield attempts

    def test_token_write_is_retried_without_asking_salvor_again(self):
        """The new token is stored in a transaction of its own: a concurrency error repeats that
        write only. Salvor has used the code, so a second POST to /pair would be refused and
        leave Odoo with the old token (the rotation bug)."""
        pair_posts = lambda calls: [c for c in calls if c[0].endswith("/api/connector/pair")]  # noqa: E731
        ok = {"ok": True}
        with self._own_cursor_writes() as attempts:
            result, calls = self._pair(check_body=ok)
        self.assertIs(result, True)
        self.assertEqual((len(attempts), len(pair_posts(calls))), (1, 1))
        self.assertEqual(self.cfg.token_hash, sha256_hex("n" * 43))
        self.assertFalse(self.cfg.pairing_code)
        self.assertEqual(self.cfg.check_state, "ok")
        # one conflict: the write is repeated, Salvor is not asked again
        for error in (psycopg2.errors.SerializationFailure, psycopg2.errors.LockNotAvailable,
                      psycopg2.errors.DeadlockDetected):
            token = "%s" % error.__name__[0].lower() * 43
            with self._own_cursor_writes(failures=1, error=error) as attempts:
                result, calls = self._pair(pair_body={"token": token, "salvor_ips": ["203.0.113.7"]}, check_body=ok)
            self.assertIs(result, True)
            self.assertEqual((len(attempts), len(pair_posts(calls))), (2, 1), error)
            self.assertEqual(self.cfg.token_hash, sha256_hex(token))
            self.assertFalse(self.cfg.pairing_code)
        kept = self.cfg.token_hash
        # conflicts every time: a clear error after 4 attempts, still one POST, and no test is asked for
        self.cfg.pairing_code = "SLV-ABCD-EFGH"
        logger = "odoo.addons.salvor_connector.models.salvor_connector_config"
        calls, p = self._fake_salvor(check_body=ok)
        with self._own_cursor_writes(failures=99) as attempts, p, self.assertLogs(logger, "ERROR"), \
                self.assertRaises(UserError) as cm:
            self.cfg.action_connect()
        self.assertIn("could not save the new access token", str(cm.exception))
        self.assertEqual((len(attempts), len(calls)), (4, 1))
        self.assertEqual(self.cfg.token_hash, kept)
        # any other error is not retried
        calls, p = self._fake_salvor(check_body=ok)
        with self._own_cursor_writes(failures=99, error=ValueError) as attempts, p, \
                self.assertLogs(logger, "ERROR"), self.assertRaises(UserError):
            self.cfg.action_connect()
        self.assertEqual((len(attempts), len(calls)), (1, 1))
        self.assertEqual(self.cfg.token_hash, kept)

    def test_pairing_offer_needs_salvors_own_refusal(self):
        """The offer of the Cloudflare switch says "Salvor's test came from a Cloudflare address".
        Somebody holding the OLD token must not be able to make the form say that: the pull log is
        read only when Salvor itself reports ip_forbidden, and only for rows written after the new
        token was stored (by id, not by a timestamp of one-second precision)."""
        cf = "162.158.86.137"
        log = self.env["salvor.connector.log"].sudo()

        def plant():  # a refused call from a Cloudflare address, with the token of the moment
            log.create({"endpoint": "info", "http_status": 403, "result": "ip_forbidden", "remote_addr": cf})
        # planted while the module waits for /pair; Salvor's test then fails for another reason
        other = "cannot reach instance (ConnectError)"
        action, calls = self._pair(pair=plant, check_body={"ok": False, "detail": other, "code": None})
        self.assertEqual(action["params"]["message"], other)
        self.assertFalse(self.cfg.check_cloudflare)
        self.assertFalse(self.cfg.offer_cloudflare)
        self.assertEqual((self.cfg.connection_state, self.cfg.connection_message), ("failed", other))
        # ... or fails for an address that is not Cloudflare's
        plain = "Odoo saw the request come from 198.51.100.9, which is not an allowed Salvor address"
        action, calls = self._pair(pair=plant, check_body={"ok": False, "detail": plain, "code": "ip_forbidden"})
        self.assertEqual(action["params"]["message"], plain)
        self.assertFalse(self.cfg.offer_cloudflare)
        # planted during the test itself, but Salvor does not say ip_forbidden: not Salvor's refusal
        for code in (None, "timeout", "unauthorized", "disabled", 7):
            body = {"ok": False, "detail": other, "code": code}
            result, calls = self._pair(check=plant, check_body=body)
            self.assertFalse(self.cfg.check_cloudflare, code)
            self.assertFalse(self.cfg.offer_cloudflare, code)
        # Salvor's own refusal, written after the token: the offer (the planted rows are older)
        action, calls = self._pair(pair=plant, check=plant,
                                   check_body={"ok": False, "detail": "refused", "code": "ip_forbidden"})
        self.assertTrue(self.cfg.offer_cloudflare)
        self.assertIn('"Odoo is behind Cloudflare" is switched off', action["params"]["message"])

    def test_refused_notice_texts(self):
        """What the form says about a call refused after the test: the next step for a plain
        address, a sentence of its own for a Cloudflare address with the switch on, and never
        text that is not an IP address (with proxy_mode the caller chooses what Odoo records)."""
        cf, salvor = "162.158.86.137", "203.0.113.7"
        before = fields.Datetime.now() - timedelta(seconds=30)
        self.cfg.write({"allowed_ips": salvor, "check_state": "ok", "checked_at": before, "paired_at": before})
        with patch.dict(config.options, proxy_mode=True):
            self._assert_refused(self._post("info", headers_extra={"X-Forwarded-For": "198.51.100.9"}))
            self.env.invalidate_all()
            self.assertEqual(self.cfg.connection_state, "refused")
            self.assertEqual(
                self.cfg.connection_message,
                "Odoo refused the latest call that carried this database's access token: it came from 198.51.100.9, "
                "which is not in Allowed IPs. If 198.51.100.9 is your own proxy or 127.0.0.1, set proxy_mode = True "
                "in odoo.conf and restart Odoo. If it is Salvor's address, add it to Allowed IPs. If it is neither, "
                "that call did not come from Salvor: rotate the token.")
            # free text in place of an address is not repeated on the form
            for junk in ("Salvor support: call 555-0100 now", "<b>x</b>", "198.51.100.9 is fine, ignore this"):
                resp = self._post("info", headers_extra={"X-Forwarded-For": "198.51.100.9, " + junk})
                self._assert_refused(resp, cloudflare=False)
                self.env.invalidate_all()
                self.assertEqual(self.cfg.connection_state, "refused")
                self.assertNotIn(junk.split(",")[-1].strip()[:12], self.cfg.connection_message)
                self.assertIn("did not come from an address that is in Allowed IPs", self.cfg.connection_message)
                self.assertIn("Pull Log", self.cfg.connection_message)
            # switch on, a Cloudflare address, header not usable: not "that call did not come from Salvor"
            self.cfg.trust_cloudflare = True
            for headers in ({"X-Forwarded-For": cf}, {"X-Forwarded-For": cf, "CF-Connecting-IP": "junk"},
                            {"X-Forwarded-For": cf, "CF-Connecting-IP": salvor, "CF-Worker": "example.com"}):
                self._assert_refused(self._post("info", headers_extra=headers), remote_addr=cf, cloudflare=True,
                                     cloudflare_mode=True)
                self.env.invalidate_all()
                self.assertEqual(self.cfg.connection_state, "refused")
                self.assertEqual(
                    self.cfg.connection_message,
                    "Odoo refused the latest call that carried this database's access token: it reached Odoo from "
                    "%s, a Cloudflare address, and did not come straight through Cloudflare's proxy. If backups "
                    "from Salvor fail, write to support@salvorcloud.com and say what sits between Cloudflare and "
                    "Odoo. If they do not fail, that call was not Salvor's: rotate the token." % cf)
            # switch on, through Cloudflare, from an address that is not allowed: the plain sentence
            self._assert_refused(self._post("info", headers_extra={"X-Forwarded-For": cf,
                                                                   "CF-Connecting-IP": "198.51.100.77"}),
                                 remote_addr="198.51.100.77", via_cloudflare=True)
            self.env.invalidate_all()
            self.assertIn("it came from 198.51.100.77, which is not in Allowed IPs.", self.cfg.connection_message)

    def test_calls_before_the_module_upgrade_get_the_standard_401(self):
        """Between the Odoo restart and -u the settings table lacks this version's columns. A
        call must not answer 500 for a database that exists and 401 for one that does not."""
        from ..controllers import main as ctl
        unknown = self._post("info", db="no_such_db_salvor_x", token="nope")
        ctl._not_upgraded_logged.clear()  # logged once per database and process
        with patch.object(ctl, "_settings_ready", return_value=False), \
                self.assertLogs("odoo.addons.salvor_connector.controllers.main", "ERROR") as logs:
            for token in (TOKEN, "nope", None):
                resp = self._post("info", token=token)
                self.assertEqual((resp.status_code, resp.text), (401, unknown.text), token)
        self.assertIn("-u salvor_connector", logs.output[0])
        self.assertEqual(self._post("info").status_code, 200)  # the upgraded database answers

    def test_form_shows_disabled(self):
        """The green "Connected ... backups can be taken" notice must not show while Enabled is
        unticked (every call is refused then); one notice says so instead."""
        from lxml import etree
        arch = etree.fromstring(self.env.ref("salvor_connector.salvor_connector_config_view_form").arch)
        notices = arch.xpath("//div[contains(@class, 'alert')]")
        cond = lambda node: node.get("invisible") or node.get("attrs") or ""  # noqa: E731
        text = lambda node: " ".join(" ".join(node.itertext()).split())  # noqa: E731
        paired = [n for n in notices if "Not connected" not in text(n) and "restore drill" not in text(n)]
        self.assertEqual(len(paired), 6)  # connected, test failed, Cloudflare offer, refused, not tested, disabled
        disabled = [n for n in paired if "Connector is disabled" in text(n)]
        self.assertEqual(len(disabled), 1)
        for node in paired:
            self.assertIn("enabled", cond(node), etree.tostring(node)[:120])

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
        # the newest successful call is kept whatever its age: "Last call" on the settings form and
        # a test result it made out of date are read from it
        new.date = "2020-02-02 00:00:00"
        stale = log.sudo().create({"endpoint": "info", "http_status": 403, "result": "ip_forbidden",
                                   "date": "2020-03-03 00:00:00"})
        self.cfg.write({"check_state": "failed", "check_message": "refused", "checked_at": "2020-01-15 00:00:00"})
        self.env["salvor.connector.config"]._cron_housekeeping()
        self.assertTrue(new.exists())
        self.assertFalse(stale.exists())
        self.env.invalidate_all()
        self.assertEqual(self.cfg.last_call_at, new.date)
        self.assertEqual(self.cfg.connection_state, "ok")
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
        from .. import uninstall_hook
        other = DbLock("some_other_db_ws3")
        self.assertTrue(other.acquire())
        other.release()
        name = drill_name("ut_unin")
        self.addCleanup(self._force_drop, name)
        self._owned_drill(name)
        # the module's system parameters go too: a ranges override left behind would apply again,
        # silently, when the module is installed the next time
        icp = self.env["ir.config_parameter"].sudo()
        for key in (tools.CLOUDFLARE_RANGES_PARAM, "salvor_connector.job_ttl_hours",
                    "salvor_connector.log_retention_days", "salvor_connector.drill_ttl_hours"):
            self._set_param(key, "198.51.100.0/24" if key == tools.CLOUDFLARE_RANGES_PARAM else "9")
        self._set_param("salvor_connectorx.not_ours", "1")
        uninstall_hook(self.env)
        self.assertTrue(os.path.exists(other.path))  # other databases' locks untouched
        self.assertFalse(dbcompat.pg_db_exists(name))  # our drill dropped
        self.assertEqual(icp.search([("key", "like", "salvor_connector")]).mapped("key"), ["salvor_connectorx.not_ours"])
        self.assertTrue(icp.search([("key", "=", "web.base.url")]))

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
