import logging
from datetime import timedelta

from odoo import _, api, fields, models
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class SalvorConnectorDrill(models.Model):
    """Drill databases THIS database's connector created. drop only accepts a
    name recorded here, so a paired database can never drop another paired
    database's drills (or anything else on the cluster)."""
    _name = "salvor.connector.drill"
    _description = "Salvor Connector Drill Database"
    _order = "id desc"

    name = fields.Char(required=True, readonly=True, index=True)
    state = fields.Selection([
        ("created", "Created"),
        ("uploading", "Uploading"),
        ("restoring", "Restoring"),
        ("restored", "Restored"),
        ("failed", "Failed"),
        ("dropped", "Dropped"),
    ], required=True, default="created", readonly=True)
    pg_oid = fields.Char(string="PostgreSQL OID", readonly=True,
                         help="Identity of the database this connector created: drop/restore "
                              "act only if a database with this name AND this oid exists.")
    archive_bytes = fields.Float(readonly=True, digits=(16, 0))
    neutralization = fields.Char(readonly=True)
    error = fields.Char(readonly=True)
    dropped_at = fields.Datetime(readonly=True)


    def _drop_owned(self, wait=10.0):
        """Drop each drill database this connector created (same name AND oid),
        stopping a running restore first; mark the record dropped. A database of
        that name we did not create is never touched. Returns the names dropped."""
        import time

        from .. import dbcompat
        from ..tools import DbLock, db_oid, drill_dir, read_state, remove_tree, terminate_state

        dropped = []
        for rec in self.filtered(lambda r: r.state != "dropped"):
            if rec.name == self.env.cr.dbname:
                continue
            path = drill_dir(self.env.cr.dbname, rec.name)
            state = read_state(path)
            if state.get("state") in ("starting", "running"):
                terminate_state(state)
            lock = DbLock(rec.name)
            deadline = time.time() + wait
            while not lock.acquire():
                if time.time() > deadline:
                    raise UserError(_("Drill database %s is busy; try again in a minute.") % rec.name)
                time.sleep(0.5)
            try:
                current = db_oid(rec.name)
                if current and current == rec.pg_oid:
                    dbcompat.drop_drill(rec.name)
                    dropped.append(rec.name)
                remove_tree(path)
                rec.write({"state": "dropped", "dropped_at": fields.Datetime.now(),
                           "error": rec.error if current in (None, rec.pg_oid) else
                           "database replaced outside the connector; not dropped"})
            finally:
                lock.release()
        return dropped

    def action_drop(self):
        if not self.env.user.has_group("base.group_system"):
            raise UserError(_("Only administrators can drop drill databases."))
        self._drop_owned()
        return True

    @api.model
    def _gc_stale(self, job_ttl_hours=6):
        """Drill databases older than salvor_connector.drill_ttl_hours (default 24)
        are dropped: Salvor drops its drill right after checking it, so one this
        old was orphaned (Disconnect mid-drill, Salvor unreachable). A drill whose
        upload or restore never finished (created, uploading, restoring, failed) is dropped, with its uploaded archive,
        after the backup job TTL (6 h), like a backup file."""
        ttl = self.env["ir.config_parameter"].sudo().get_int("salvor_connector.drill_ttl_hours", 24) or 24
        cutoff = fields.Datetime.now() - timedelta(hours=max(ttl, 1))
        unfinished = fields.Datetime.now() - timedelta(hours=max(job_ttl_hours, 1))
        stale = self.sudo().search([("state", "!=", "dropped"), "|", ("create_date", "<", cutoff),
                                    "&", ("state", "in", ("created", "uploading", "restoring", "failed")),
                                    ("create_date", "<", unfinished)])
        for rec in stale:
            try:
                rec._drop_owned(wait=0)
            except UserError:
                _logger.info("salvor_connector: stale drill %s busy, retried next run", rec.name)
