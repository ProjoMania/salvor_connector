"""Version-specific database helpers (Odoo 20.0: odoo.modules.db).

In 20 the database service moved to odoo.modules.db (no list_db decorator
on dump/restore/drop any more). ``restore`` only accepts Odoo zip backups,
so a ``pg_dump -Fc`` drill is restored here with pg_restore. Callers must
already have validated ``name`` against tools.DRILL_RE.
"""
import logging
import os
import shutil
import subprocess
from contextlib import closing

from psycopg2 import sql

import odoo
from odoo import api, SUPERUSER_ID
from odoo.modules import db as odoo_db
from odoo.modules.registry import Registry
from odoo.tools import config
from odoo.tools.misc import exec_pg_environ, find_pg_tool

_logger = logging.getLogger(__name__)


def _system_db():
    return config["db_system"] or "postgres"


def list_dbs():
    return odoo_db.list_dbs(force=True)


def dump_manifest(cr):
    return odoo_db._dump_db_manifest(cr)


def pg_db_exists(name):
    with closing(odoo.sql_db.db_connect(_system_db()).cursor()) as cr:
        cr.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
        return bool(cr.fetchone())


def restore_drill(name, path):
    with open(path, "rb") as fh:
        magic = fh.read(5)
    if magic != b"PGDMP":
        odoo_db.restore(name, path, copy=True)
        return
    odoo_db._create_empty_database(name)
    subprocess.run([find_pg_tool("pg_restore"), "--no-owner", "--dbname=" + name, path],
                   env=exec_pg_environ(), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
    registry = Registry.new(name)
    with registry.cursor() as cr:
        env = api.Environment(cr, SUPERUSER_ID, {})
        env["ir.config_parameter"].init(force=True)  # new dbuuid, like copy=True


def drop_drill(name):
    Registry.delete(name)
    odoo.sql_db.close_db(name)
    with closing(odoo.sql_db.db_connect(_system_db()).cursor()) as cr:
        cr._cnx.autocommit = True
        cr.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                   "WHERE datname = %s AND pid != pg_backend_pid()", (name,))
        cr.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
    _logger.info("salvor_connector: dropped drill database %s", name)
    fs = config.filestore(name)
    if os.path.isdir(fs):
        shutil.rmtree(fs)
