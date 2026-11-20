import logging
import re
import threading
import time

import psycopg2.errors
import requests

from odoo import _, api, fields, models, release
from odoo import modules as odoo_modules
from odoo.exceptions import UserError

from .. import tools
from ..tools import (JOB_TTL_HOURS_DEFAULT, PROTOCOL_VERSION, is_ip_or_cidr, parse_ips, sha256_hex,
                     sweep_drill_files, sweep_jobs)

_logger = logging.getLogger(__name__)

PAIRING_CODE_RE = re.compile(r"^SLV-[A-Z0-9]{4}-[A-Z0-9]{4}$")
DEFAULT_SALVOR_URL = "https://app.salvorcloud.com"
LOG_MODEL = "salvor.connector.log"
# the short write of the own transaction is tried again on these, and only on these
PG_RETRY_ERRORS = (psycopg2.errors.SerializationFailure, psycopg2.errors.DeadlockDetected,
                   psycopg2.errors.LockNotAvailable)
OWN_TRANSACTION_ATTEMPTS = 4
CHECK_STATES = [("ok", "Reachable"), ("failed", "Not reachable"),
                ("timeout", "Test timed out"), ("unknown", "Not tested")]
# what the form shows can also be a later call that Odoo refused for its address
CONNECTION_STATES = CHECK_STATES[:2] + [("refused", "Last call refused")] + CHECK_STATES[2:]
_warned_ranges = set()


def cloudflare_nets_from(text):
    """The networks treated as Cloudflare's, from the text of the system parameter
    salvor_connector.cloudflare_ranges: that list when it is valid, else the built-in one
    (said once per value in the server log). No database access."""
    nets, error = tools.cloudflare_nets(text)
    if error and text not in _warned_ranges:
        _warned_ranges.add(text)
        _logger.warning("salvor_connector: system parameter %s is ignored (%s); the built-in "
                        "Cloudflare ranges are used", tools.CLOUDFLARE_RANGES_PARAM, error)
    return nets


def _in_test():
    # a test's cursor must not commit; there the test shares it with the server anyway
    return bool(odoo_modules.module.current_test or getattr(threading.current_thread(), "testing", False))


def _salvor_message(resp):
    """Salvor's explanation from an error answer: FastAPI's {"detail": str | [{"msg"}]},
    or the connector-style {"message"/"error"}. Plain text, at most 300 characters."""
    try:
        data = resp.json()
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    detail = data.get("detail")
    if isinstance(detail, list):
        detail = "; ".join(str(d.get("msg") if isinstance(d, dict) else d) for d in detail[:3])
    return str(detail or data.get("message") or data.get("error") or "")[:300]


class SalvorConnectorConfig(models.Model):
    _name = "salvor.connector.config"
    _description = "Salvor Connector Settings"

    name = fields.Char(default="Salvor Connector", readonly=True)
    salvor_url = fields.Char(string="Salvor URL", default=DEFAULT_SALVOR_URL, required=True)
    pairing_code = fields.Char(help="One-time code shown by Salvor (SLV-XXXX-XXXX). Not kept after Connect.")
    token_hash = fields.Char(readonly=True, copy=False)
    paired_at = fields.Datetime(readonly=True, copy=False)
    instance_id = fields.Char(string="Salvor Instance", readonly=True, copy=False)
    allowed_ips = fields.Text(
        string="Allowed IPs", copy=False,
        help="Salvor source addresses or CIDR ranges, comma or newline separated. "
             "Requests from any other address are refused (empty = refuse all).")
    # Not a setting any more (restore drills were removed in 2.0.4). The field stays so the
    # settings form of an older version, still in the database between the Odoo restart and
    # -u salvor_connector, renders instead of crashing the web client. Always false.
    drill_enabled = fields.Boolean(string="Allow restore drills (removed)", compute="_compute_drill_enabled")

    def _compute_drill_enabled(self):
        for rec in self:
            rec.drill_enabled = False
    enabled = fields.Boolean(default=True)
    trust_cloudflare = fields.Boolean(
        string="Odoo is behind Cloudflare", default=False, copy=False,
        help="Off by default. Switch it on only if this Odoo is reached through Cloudflare's proxy "
             "(through a Cloudflare Tunnel it has no effect). With it on, when a request reaches Odoo "
             "from a Cloudflare address, the address check relies on the CF-Connecting-IP header that "
             "Cloudflare adds, which does not show that a request came through your own zone: the "
             "access token remains the protection. To let only your own zone reach Odoo, set up "
             "zone-level or per-hostname Authenticated Origin Pulls.")
    # Read from the pull log: calls from Salvor never write this row (a write here from
    # another transaction is what used to break a pairing or rotation in progress).
    last_call_at = fields.Datetime(compute="_compute_last_call_at")
    is_paired = fields.Boolean(compute="_compute_is_paired")
    # The result of the test made at pairing, as stored then.
    check_state = fields.Selection(CHECK_STATES, string="Connection test", readonly=True, copy=False)
    check_message = fields.Char(string="Connection test result", readonly=True, copy=False)
    checked_at = fields.Datetime(string="Pairing test at", readonly=True, copy=False)
    # The test call was refused from a Cloudflare address while "Odoo is behind Cloudflare" was off.
    check_cloudflare = fields.Boolean(readonly=True, copy=False)
    # What the form shows: the stored result, unless something that happened since replaces it
    # (a call from Salvor that got through, a call refused for its address, the Cloudflare switch).
    connection_state = fields.Selection(CONNECTION_STATES, string="Connection", compute="_compute_connection")
    connection_message = fields.Char(compute="_compute_connection")
    offer_cloudflare = fields.Boolean(compute="_compute_connection")

    @api.depends("token_hash")
    def _compute_is_paired(self):
        for rec in self:
            rec.is_paired = bool(rec.token_hash)

    def _next_test(self):
        # a method, not a module function: Odoo reads the language from the caller's ``self``
        return _("Choose Test connection in Salvor, or run a backup from Salvor.")

    def _last_ok_call(self):
        """The pull-log row of the last call that got an answer other than a refusal."""
        return self.env[LOG_MODEL].sudo().search([("http_status", "<", 400)], order="id desc", limit=1)

    def _compute_last_call_at(self):
        last_ok = self._last_ok_call().date or False
        for rec in self:
            rec.last_call_at = last_ok

    @api.depends("token_hash", "check_state", "check_message", "checked_at", "check_cloudflare", "trust_cloudflare",
                 "paired_at")
    def _compute_connection(self):
        log = self.env[LOG_MODEL].sudo()
        last_ok = self._last_ok_call()
        # the newest call refused for its address; only a caller holding the token gets that far
        refused = log.search([("result", "=", "ip_forbidden")], order="id desc", limit=1)
        if refused and last_ok and last_ok.id > refused.id:
            refused = log.browse()  # a call has got through since
        for rec in self:
            state, message, offer = rec.check_state, rec.check_message, False
            if not rec.token_hash:
                state = message = False
            elif state and state != "ok" and last_ok and rec.checked_at and last_ok.date > rec.checked_at:
                # a later call got through: a failed or missing test result is out of date
                state, message = "ok", _("Salvor has reached this database since the test.")
            elif state == "failed" and rec.check_cloudflare and rec.trust_cloudflare:
                state = "unknown"
                message = _("\"Odoo is behind Cloudflare\" was switched on after the test. %s", self._next_test())
            elif state == "failed" and rec.check_cloudflare:
                offer = True  # Salvor's own test call, at pairing, came from a Cloudflare address
            since = rec.checked_at or rec.paired_at
            if rec.token_hash and refused and not offer and (not since or refused.date > since):
                # Later than the test and than every call that got through. It says what Odoo
                # saw, not who called: the button is offered for Salvor's own test only.
                state = "refused"
                # With proxy_mode on and Odoo's own port reachable, the caller chooses what Odoo
                # records as the address: only an IP address is repeated here.
                addr = tools.ip_text(refused.remote_addr)
                cloudflare = bool(addr) and tools.is_cloudflare(addr, rec._cloudflare_nets())
                if not addr:
                    message = _(
                        "Odoo refused the latest call that carried this database's access token: it did not "
                        "come from an address that is in Allowed IPs. The Pull Log shows what Odoo recorded "
                        "for it.")
                elif cloudflare and not rec.trust_cloudflare:
                    message = _(
                        "Odoo refused the latest call that carried this database's access token: it came "
                        "from %(addr)s, a Cloudflare address, and \"Odoo is behind Cloudflare\" is switched "
                        "off. If this Odoo is behind Cloudflare, switch it on below. If it is not, that call "
                        "did not come from Salvor's address: rotate the token.", addr=addr)
                elif cloudflare:
                    # switch on, and the header was missing, not one address, or came with CF-Worker
                    message = _(
                        "Odoo refused the latest call that carried this database's access token: it reached "
                        "Odoo from %(addr)s, a Cloudflare address, and did not come straight through "
                        "Cloudflare's proxy. If backups from Salvor fail, write to support@salvorcloud.com "
                        "and say what sits between Cloudflare and Odoo. If they do not fail, that call was "
                        "not Salvor's: rotate the token.", addr=addr)
                else:
                    message = _(
                        "Odoo refused the latest call that carried this database's access token: it came "
                        "from %(addr)s, which is not in Allowed IPs. If %(addr)s is your own proxy or "
                        "127.0.0.1, set proxy_mode = True in odoo.conf and restart Odoo. If it is Salvor's "
                        "address, add it to Allowed IPs. If it is neither, that call did not come from "
                        "Salvor: rotate the token.", addr=addr)
            rec.connection_state = state
            rec.connection_message = message
            rec.offer_cloudflare = offer

    def _cloudflare_ranges_text(self):
        return self.env["ir.config_parameter"].sudo().get_param(tools.CLOUDFLARE_RANGES_PARAM)

    def _cloudflare_nets(self):
        """The networks treated as Cloudflare's: the built-in list, or the system
        parameter salvor_connector.cloudflare_ranges when it holds a valid list."""
        return cloudflare_nets_from(self._cloudflare_ranges_text())

    @api.model
    def _get_singleton(self):
        rec = self.env.ref("salvor_connector.salvor_connector_config_main", raise_if_not_found=False)
        return rec or self.search([], limit=1, order="id")

    @api.model_create_multi
    def create(self, vals_list):
        if self.sudo().search_count([]) + len(vals_list) > 1:
            raise UserError(_("Only one Salvor Connector configuration can exist."))
        return super().create(vals_list)

    @api.constrains("allowed_ips")
    def _check_allowed_ips(self):
        for rec in self:
            for item in re.split(r"[\s,;]+", rec.allowed_ips or ""):
                if item and not parse_ips(item):
                    raise UserError(_("Invalid IP address or range: %s", item))

    @api.model
    def action_open(self):
        rec = self._get_singleton()
        return {
            "type": "ir.actions.act_window",
            "name": _("Salvor Connector"),
            "res_model": self._name,
            "res_id": rec.id,
            "view_mode": "form",
            "target": "current",
        }

    def _module_version(self):
        mod = self.env["ir.module.module"].sudo().search([("name", "=", "salvor_connector")], limit=1)
        return mod.latest_version or mod.installed_version or ""

    def _in_own_transaction(self, func):
        """Run ``func(record)`` in a short transaction of its own, commit it, and
        return what it returned.

        Writing the settings row from the button's own transaction fails with a
        serialization error as soon as anything else touched the row since that
        transaction began, and Odoo then runs the whole button again: a second
        redemption of a pairing code that is already used. So the button's
        transaction writes nothing after the call to Salvor; what must be kept is
        written here, on a fresh snapshot, and a concurrency error repeats this
        write alone, never the call to Salvor.
        """
        if _in_test():
            return func(self)  # the test's cursor is the only one that sees its data
        return self._retry_in_own_cursor(func)

    def _retry_in_own_cursor(self, func):
        for attempt in range(1, OWN_TRANSACTION_ATTEMPTS + 1):
            try:
                with self.env.registry.cursor() as cr:
                    # never wait for ever on a row somebody else holds: give up, try again
                    cr.execute("SET LOCAL lock_timeout = '5s'")
                    # keep the record (and so its environment) referenced until the flush:
                    # Odoo 16 holds a transaction's environments weakly
                    rec = self.with_env(self.env(cr=cr))
                    result = func(rec)
                    rec.flush_recordset()
                break
            except PG_RETRY_ERRORS as e:
                if attempt == OWN_TRANSACTION_ATTEMPTS:
                    raise
                _logger.info("salvor_connector: settings write hit %s, trying again (%s/%s)",
                             e.__class__.__name__, attempt, OWN_TRANSACTION_ATTEMPTS)
                time.sleep(0.2 * attempt)
        self.invalidate_recordset()
        return result

    def action_connect(self):
        self.ensure_one()
        if not self.env.user.has_group("base.group_system"):
            raise UserError(_("Only administrators can pair the Salvor Connector."))
        code = (self.pairing_code or "").strip().upper()
        if not PAIRING_CODE_RE.match(code):
            raise UserError(_("The pairing code must look like SLV-XXXX-XXXX."))
        base = (self.salvor_url or "").strip().rstrip("/")
        if not base.startswith("https://"):
            raise UserError(_("The Salvor URL must start with https://"))
        # Everything read from the database is read here, before the calls to Salvor.
        dbname = self.env.cr.dbname
        odoo_url = self.env["ir.config_parameter"].sudo().get_param("web.base.url")
        payload = {
            "code": code,
            "odoo_url": odoo_url,
            "db": dbname,
            "odoo_version": release.version,
            "module_version": self._module_version(),
            "protocol": PROTOCOL_VERSION,
        }
        if not _in_test():
            # End this request's transaction before talking to Salvor: nothing of it may be
            # pending or holding a lock when the token is written from its own transaction,
            # and nothing is read from the database between here and Salvor's call-back.
            self.env.cr.commit()
        try:
            resp = requests.post(base + "/api/connector/pair", json=payload, timeout=30, verify=True)
        except requests.RequestException as e:
            raise UserError(_("Could not reach Salvor: %s", e.__class__.__name__)) from None
        if resp.status_code != 200:
            message = _salvor_message(resp)
            if message.startswith("odoo_url: "):
                # Salvor's name for the address this database sent: say which setting that is
                message = _("This database gave Salvor the address %(url)s (system parameter web.base.url). "
                            "%(message)s", url=str(odoo_url or "")[:200], message=message[len("odoo_url: "):])
            raise UserError(_("Salvor did not complete the pairing (HTTP %(status)s). %(message)s",
                              status=resp.status_code, message=message))
        # Salvor answered 200: it may have used the code, so say what to do next
        unexpected = _("Unexpected answer from Salvor. The pairing is not complete: create a new pairing code "
                       "in Salvor and connect again.")
        try:
            data = resp.json()
            token = data["token"]
            ips = data.get("salvor_ips")
        except (ValueError, KeyError, TypeError, AttributeError):
            raise UserError(unexpected) from None
        if not isinstance(token, str) or len(token) < 32:
            raise UserError(unexpected)
        instance_id = str(data.get("instance_id") or "")
        salvor_url = str(data.get("salvor_url") or "")
        vals = {
            "token_hash": sha256_hex(token),
            # only what the Allowed IPs check accepts: nothing in Salvor's answer may make this write fail
            "allowed_ips": "\n".join(ip.strip() for ip in (ips if isinstance(ips, list) else [])
                                     if isinstance(ip, str) and is_ip_or_cidr(ip)),
            "instance_id": instance_id,
            "paired_at": fields.Datetime.now(),
            "salvor_url": salvor_url.rstrip("/") if salvor_url.startswith("https://") else base,
            "pairing_code": False,
            "enabled": True,
            "check_state": False, "check_message": False, "checked_at": False, "check_cloudflare": False,
        }
        # Salvor has used the code and holds the new token from here on: store it at once, in a
        # transaction of its own. The code is cleared in the same write, so if Odoo ever ran this
        # button again it would stop at the code check above and never ask Salvor a second time.
        try:
            self._in_own_transaction(lambda rec: rec.write(vals))
        except Exception:  # noqa: BLE001
            _logger.exception("salvor_connector: the new token could not be stored (db=%s)", dbname)
            raise UserError(_(
                "Salvor accepted the pairing code, but this database could not save the new access "
                "token, so the pairing is not complete. Create a new pairing code in Salvor and connect "
                "again.")) from None
        _logger.info("Salvor Connector paired (db=%s, instance=%s)", dbname, instance_id)
        # The token is committed: Salvor, calling from its own servers in other transactions,
        # can now show that it gets through. Its calls do not write the settings row.
        # Every pull-log row above this mark was written after the old token stopped working.
        mark = self._newest_log_id()
        state, message, code = self._check_reachability(base, token, dbname, instance_id)
        del token
        offer = self._store_check(state, message, code, mark)
        if state == "failed":
            if offer:
                message = _(
                    "Odoo refused Salvor's connection test: the request reached Odoo from a Cloudflare "
                    "address, and \"Odoo is behind Cloudflare\" is switched off. If this Odoo is behind "
                    "Cloudflare, switch it on with the button on this form.")
            return {"type": "ir.actions.client", "tag": "display_notification", "params": {
                "type": "warning", "sticky": True,
                "title": _("Paired, but Salvor cannot reach this database"),
                "message": message,
                "next": {"type": "ir.actions.client", "tag": "soft_reload"}}}
        return True

    def _check_reachability(self, base, token, dbname, instance_id):
        """Ask Salvor to call /salvor/v1/info with the new token right now.

        Returns (state, message, code): state is "ok", "failed" (Salvor tried and
        says why), "timeout" (the test did not finish, so nothing is known) or
        "unknown" (no test was made); code is Salvor's short reason, when it gave
        one ("ip_forbidden", "timeout", ...). Takes everything as arguments: no
        database access happens between the commit of the token and Salvor's call.
        """
        try:
            resp = requests.post(base + "/api/connector/pair/check",
                                 json={"db": dbname, "instance_id": instance_id},
                                 headers={"Authorization": "Bearer " + token}, timeout=60, verify=True)
        except requests.ReadTimeout as e:  # Salvor was reached and was still testing
            return "timeout", _("Salvor did not answer the test request in time (%(error)s). %(next)s",
                                error=e.__class__.__name__, next=self._next_test()), None
        except requests.RequestException as e:
            return "unknown", _("Could not ask Salvor to test the connection (%(error)s). %(next)s",
                                error=e.__class__.__name__, next=self._next_test()), None
        if resp.status_code == 404:
            return "unknown", _("This Salvor does not test the connection at pairing; the first backup will."), None
        if resp.status_code != 200:
            return "unknown", _("Salvor could not run the connection test (HTTP %(status)s). %(next)s %(message)s",
                                status=resp.status_code, next=self._next_test(), message=_salvor_message(resp)).strip(), None
        try:
            data = resp.json()
        except ValueError:
            data = None
        if not isinstance(data, dict):
            return "unknown", _("Unexpected answer from Salvor to the test request. %s", self._next_test()), None
        message = str(data.get("detail") or "")[:500]
        code = data.get("code") if isinstance(data.get("code"), str) else None
        if data.get("ok") is True:
            return "ok", message or _("Salvor reached this database."), code
        if code == "timeout":
            # Odoo did not answer Salvor in time. With a single worker that says nothing about
            # the connection: the worker is busy with this very request.
            return "timeout", message or _(
                "Odoo did not answer Salvor's test in time. If Odoo runs with one worker, it cannot "
                "answer while it waits for this test. %s", self._next_test()), code
        return "failed", message or _("Salvor could not reach this database."), code

    def _newest_log_id(self):
        """The highest pull-log id committed so far (0 for an empty log), read in a
        transaction of its own; None if it cannot be read."""
        try:
            return self._in_own_transaction(
                lambda rec: rec.env[LOG_MODEL].sudo().search([], order="id desc", limit=1).id or 0)
        except Exception:  # noqa: BLE001
            _logger.warning("salvor_connector: could not read the pull log", exc_info=True)
            return None

    def _store_check(self, state, message, code, mark):
        """Keep the result of the test in its own transaction. Returns True when the
        test was refused from a Cloudflare address while "Odoo is behind Cloudflare"
        is off (the form then offers the switch). Never raises: the pairing is
        already stored, and the result is advice.

        The offer says "Salvor's test came from a Cloudflare address", so it rests on
        Salvor's own answer (code ip_forbidden) and, for the address, on the pull-log
        rows above ``mark``: those were written after the new token was stored, when
        the old token no longer got as far as the address check (a call that was
        already past the token check at that instant is the one exception)."""
        def store(rec):
            offer = False
            if state == "failed" and code == "ip_forbidden" and not rec.trust_cloudflare:
                nets = rec._cloudflare_nets()
                # what this database itself saw of the test call: its own pull log
                refusal = rec.env[LOG_MODEL].sudo().browse()
                if mark is not None:
                    refusal = refusal.search([("result", "=", "ip_forbidden"), ("id", ">", mark)],
                                             order="id desc", limit=1)
                if refusal:
                    offer = tools.is_cloudflare(refusal.remote_addr, nets)
                else:
                    # no row (the pull log keeps at most 30 refusals a minute): Salvor's text
                    # repeats the address this database reported to it
                    offer = any(tools.is_cloudflare(word.strip("()[],.;:'\""), nets) for word in message.split())
            rec.write({"check_state": state, "check_message": message,
                       "checked_at": fields.Datetime.now(), "check_cloudflare": offer})
            return offer
        try:
            return self._in_own_transaction(store)
        except Exception:  # noqa: BLE001
            _logger.warning("salvor_connector: could not store the connection test result", exc_info=True)
            return False

    def action_trust_cloudflare(self):
        """The switch offered when the connection test was refused from a Cloudflare address."""
        self.ensure_one()
        if not self.env.user.has_group("base.group_system"):
            raise UserError(_("Only administrators can change the Salvor Connector settings."))
        self.write({"trust_cloudflare": True})
        return True

    def action_rotate(self):
        """Rotate the token without a gap: Salvor (database menu → Rotate token)
        issues a pairing code bound to this database; redeeming it here
        replaces the token hash in one write, so the old token stops working
        the moment the new one exists."""
        self.ensure_one()
        if not (self.pairing_code or "").strip():
            raise UserError(_(
                "To rotate the token, open this database in Salvor, choose \"Rotate token\", "
                "paste the new pairing code above and click Rotate token again. The current token "
                "keeps working until then. To cut Salvor off immediately, use Disconnect."))
        return self.action_connect()

    def action_view_log(self):
        return self.env["ir.actions.act_window"]._for_xml_id("salvor_connector.action_salvor_connector_log")

    @api.model
    def _job_ttl_hours(self):
        value = self.env["ir.config_parameter"].sudo().get_param(
            "salvor_connector.job_ttl_hours", JOB_TTL_HOURS_DEFAULT)
        try:
            return max(int(value), 1)
        except (TypeError, ValueError):
            return JOB_TTL_HOURS_DEFAULT

    @api.model
    def _cron_housekeeping(self):
        """Hourly: expire backup job files, old pull-log rows and orphaned drill databases."""
        removed = sweep_jobs(self.env.cr.dbname, self._job_ttl_hours())
        if removed:
            _logger.info("salvor_connector: removed %s expired backup job(s)", removed)
        self.env["salvor.connector.log"]._gc_old_rows()
        self.env["salvor.connector.drill"]._gc_stale(self._job_ttl_hours())

    leftover_drill_count = fields.Integer(compute="_compute_leftover_drill_count")

    def _compute_leftover_drill_count(self):
        count = self.env["salvor.connector.drill"].sudo().search_count([("state", "!=", "dropped")])
        for rec in self:
            rec.leftover_drill_count = count

    def action_drop_drills(self):
        """Drop leftover drill databases this database created (oid-checked)."""
        self.ensure_one()
        if not self.env.user.has_group("base.group_system"):
            raise UserError(_("Only administrators can drop drill databases."))
        dropped = self.env["salvor.connector.drill"].sudo().search(
            [("state", "!=", "dropped")])._drop_owned()
        return {"type": "ir.actions.client", "tag": "display_notification", "params": {
            "type": "info", "message": _("%s drill database(s) dropped.") % len(dropped)}}

    def action_disconnect(self):
        self.ensure_one()
        self.write({"token_hash": False, "paired_at": False, "instance_id": False, "pairing_code": False,
                    "allowed_ips": False, "check_state": False, "check_message": False, "checked_at": False,
                    "check_cloudflare": False})
        # revoking also stops running backup jobs and deletes their files now
        sweep_jobs(self.env.cr.dbname, 0)
        # ...drops the drill databases it created
        # (oid-checked) and deletes uploaded drill archives: Salvor can no longer ask
        for drill in self.env["salvor.connector.drill"].sudo().search([("state", "!=", "dropped")]):
            try:
                drill._drop_owned()
            except UserError:
                _logger.warning("salvor_connector: drill %s busy at disconnect; the housekeeping drops it",
                                drill.name)
        sweep_drill_files(self.env.cr.dbname)
        _logger.info("Salvor Connector disconnected (db=%s)", self.env.cr.dbname)
        return True
