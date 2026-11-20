from datetime import timedelta

from odoo import api, fields, models

DEFAULT_RETENTION_DAYS = 90
REFUSED_RETENTION_DAYS = 14
MAX_ROWS = 200000


class SalvorConnectorLog(models.Model):
    """One row per call Salvor makes to this database, and refusals for it:
    at most 30 refusal rows per minute (more go to the server log only), and
    none for a call naming a database that does not host the connector.
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
        value = self.env["ir.config_parameter"].sudo().get_param(
            "salvor_connector.log_retention_days", DEFAULT_RETENTION_DAYS)
        try:
            return max(int(value), 1)
        except (TypeError, ValueError):
            return DEFAULT_RETENTION_DAYS

    @api.model
    def _gc_old_rows(self):
        now = fields.Datetime.now()
        # The newest successful call stays whatever its age: "Last call" and the connection
        # state on the settings form are read from it (calls do not write the settings row).
        last_ok = self.sudo().search([("http_status", "<", 400)], order="id desc", limit=1)
        self.sudo().search([("date", "<", now - timedelta(days=self._retention_days())),
                            ("id", "not in", last_ok.ids)]).unlink()
        # refusals (anyone can cause them) are kept for a shorter time
        days = min(REFUSED_RETENTION_DAYS, self._retention_days())
        self.sudo().search([("http_status", ">=", 400), ("date", "<", now - timedelta(days=days))]).unlink()
        # hard cap: evict refusals first (anyone can cause them), oldest first, so a
        # flood never pushes out the history of successful calls
        self.env.cr.execute("SELECT count(*) FROM salvor_connector_log")
        excess = self.env.cr.fetchone()[0] - MAX_ROWS
        if excess > 0:
            self.env.cr.execute("DELETE FROM salvor_connector_log WHERE id IN (SELECT id FROM salvor_connector_log "
                                "WHERE http_status >= 400 ORDER BY id LIMIT %s)", (excess,))
            excess -= self.env.cr.rowcount
        if excess > 0:
            self.env.cr.execute("DELETE FROM salvor_connector_log WHERE id IN (SELECT id FROM salvor_connector_log "
                                "ORDER BY id LIMIT %s)", (excess,))
