"""Version-specific database helpers (Odoo 17.0 - 19.0: odoo.service.db).

odoo.service.db gates dump_db_manifest / restore_db / exp_drop behind
``list_db`` (check_db_management_enabled) and exp_drop/list_dbs only see the
databases exposed by ``--database`` when no dbfilter is set, so drill
databases are checked and dropped here directly. Callers must already have
validated ``name`` against tools.DRILL_RE.
"""
import logging
import os
import shutil
from contextlib import closing

from psycopg2 import sql

import odoo
from odoo.modules.registry import Registry
from odoo.service import db as db_service
from odoo.tools import config

_logger = logging.getLogger(__name__)
SYSTEM_DB = "postgres"


def _unwrap(func):
    return getattr(func, "__wrapped__", func)


def list_dbs():
    return db_service.list_dbs(True)


def dump_manifest(cr):
    return _unwrap(db_service.dump_db_manifest)(cr)


def pg_db_exists(name):
    with closing(odoo.sql_db.db_connect(SYSTEM_DB).cursor()) as cr:
        cr.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
        return bool(cr.fetchone())


def restore_drill(name, path):
    _unwrap(db_service.restore_db)(name, path, copy=True)


def drop_drill(name):
    Registry.delete(name)
    odoo.sql_db.close_db(name)
    with closing(odoo.sql_db.db_connect(SYSTEM_DB).cursor()) as cr:
        cr._cnx.autocommit = True
        cr.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                   "WHERE datname = %s AND pid != pg_backend_pid()", (name,))
        cr.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
    _logger.info("salvor_connector: dropped drill database %s", name)
    fs = config.filestore(name)
    if os.path.isdir(fs):
        shutil.rmtree(fs)
