from datetime import timedelta

from odoo import api, fields, models

DEFAULT_RETENTION_DAYS = 90


class SalvorConnectorLog(models.Model):
    """One row per call Salvor makes to this database (and every refusal).
    Never contains the token or its hash."""
    _name = "salvor.connector.log"
    _description = "Salvor Connector Pull Log"
    _order = "id desc"
    _log_access = False

    date = fields.Datetime(required=True, default=fields.Datetime.now, readonly=True, index=True)
    endpoint = fields.Char(required=True, readonly=True)
    http_status = fields.Integer(string="HTTP status", readonly=True)
    result = fields.Char(readonly=True, help="ok, or the refusal code sent to Salvor")
    remote_addr = fields.Char(string="Source IP", readonly=True)
    job_id = fields.Char(string="Job", readonly=True)
    bytes = fields.Float(readonly=True, digits=(16, 0))
    detail = fields.Char(readonly=True)

    @api.model
    def _retention_days(self):
        value = self.env["ir.config_parameter"].sudo().get_int(
            "salvor_connector.log_retention_days", DEFAULT_RETENTION_DAYS)
        try:
            return max(int(value), 1)
        except (TypeError, ValueError):
            return DEFAULT_RETENTION_DAYS

    @api.model
    def _gc_old_rows(self):
        limit = fields.Datetime.now() - timedelta(days=self._retention_days())
        self.sudo().search([("date", "<", limit)]).unlink()
