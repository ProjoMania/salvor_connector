import logging
import re

import requests

from odoo import _, api, fields, models, release
from odoo.exceptions import UserError

from ..tools import JOB_TTL_HOURS_DEFAULT, PROTOCOL_VERSION, parse_ips, sha256_hex, sweep_jobs

_logger = logging.getLogger(__name__)

PAIRING_CODE_RE = re.compile(r"^SLV-[A-Z0-9]{4}-[A-Z0-9]{4}$")
DEFAULT_SALVOR_URL = "https://app.salvorcloud.com"


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
    drill_enabled = fields.Boolean(
        string="Allow restore drills", default=False,
        help="Lets Salvor restore a backup of this database into a NEW database named "
             "salvor_drill_* on this PostgreSQL server (created only if the name is free), "
             "neutralize it (crons and outgoing mail off, pairing cleared) and drop it afterwards. "
             "The connector never restores over or drops the live database, and can only drop "
             "drill databases it created. Needs the CREATEDB privilege and free disk of 2.5x "
             "the backup size.")
    enabled = fields.Boolean(default=True)
    last_call_at = fields.Datetime(readonly=True, copy=False)
    is_paired = fields.Boolean(compute="_compute_is_paired")

    @api.depends("token_hash")
    def _compute_is_paired(self):
        for rec in self:
            rec.is_paired = bool(rec.token_hash)

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
        payload = {
            "code": code,
            "odoo_url": self.env["ir.config_parameter"].sudo().get_str("web.base.url"),
            "db": self.env.cr.dbname,
            "odoo_version": release.version,
            "module_version": self._module_version(),
            "protocol": PROTOCOL_VERSION,
        }
        try:
            resp = requests.post(base + "/api/connector/pair", json=payload, timeout=30, verify=True)
        except requests.RequestException as e:
            raise UserError(_("Could not reach Salvor: %s", e.__class__.__name__)) from None
        if resp.status_code != 200:
            message = ""
            try:
                message = str(resp.json().get("message") or resp.json().get("error") or "")[:200]
            except ValueError:
                pass
            raise UserError(_("Salvor refused the pairing code (HTTP %(status)s). %(message)s",
                              status=resp.status_code, message=message))
        try:
            data = resp.json()
            token = data["token"]
            ips = data.get("salvor_ips") or []
        except (ValueError, KeyError, TypeError):
            raise UserError(_("Unexpected answer from Salvor.")) from None
        if not isinstance(token, str) or len(token) < 32:
            raise UserError(_("Unexpected answer from Salvor."))
        self.write({
            "token_hash": sha256_hex(token),
            "allowed_ips": "\n".join(str(ip) for ip in ips if isinstance(ip, str)),
            "instance_id": str(data.get("instance_id") or ""),
            "paired_at": fields.Datetime.now(),
            "salvor_url": (data.get("salvor_url") or base).rstrip("/")
            if str(data.get("salvor_url") or "").startswith("https://") else base,
            "pairing_code": False,
            "enabled": True,
        })
        del token
        _logger.info("Salvor Connector paired (db=%s, instance=%s)", self.env.cr.dbname, self.instance_id)
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
        value = self.env["ir.config_parameter"].sudo().get_int(
            "salvor_connector.job_ttl_hours", JOB_TTL_HOURS_DEFAULT)
        try:
            return max(int(value), 1)
        except (TypeError, ValueError):
            return JOB_TTL_HOURS_DEFAULT

    @api.model
    def _cron_housekeeping(self):
        """Daily: expire backup job files of this database and old pull-log rows."""
        removed = sweep_jobs(self.env.cr.dbname, self._job_ttl_hours())
        if removed:
            _logger.info("salvor_connector: removed %s expired backup job(s)", removed)
        self.env["salvor.connector.log"]._gc_old_rows()

    def action_disconnect(self):
        self.ensure_one()
        self.write({"token_hash": False, "paired_at": False, "instance_id": False, "pairing_code": False})
        # revoking also stops running backup jobs and deletes their files now
        sweep_jobs(self.env.cr.dbname, 0)
        _logger.info("Salvor Connector disconnected (db=%s)", self.env.cr.dbname)
        return True
