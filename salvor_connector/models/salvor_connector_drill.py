from odoo import fields, models


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
    archive_bytes = fields.Float(readonly=True, digits=(16, 0))
    neutralization = fields.Char(readonly=True)
    error = fields.Char(readonly=True)
    dropped_at = fields.Datetime(readonly=True)

