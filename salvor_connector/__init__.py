from . import models
from . import controllers



def uninstall_hook(env):
    """Clean up THIS database only: drop the drill databases it created (when
    the database with that name is still the one we created, same oid), stop
    its running jobs and delete its job and drill files. Lock files are left
    alone: they are empty and shared by other databases' running jobs."""
    import logging
    import os
    import shutil

    from . import dbcompat
    from .tools import DbLock, db_oid, drill_dir, jobs_root, read_state, terminate_state

    log = logging.getLogger(__name__)
    dbname = env.cr.dbname
    for rec in env["salvor.connector.drill"].sudo().search([("state", "!=", "dropped")]):
        path = drill_dir(dbname, rec.name)
        state = read_state(path)
        if state.get("state") in ("starting", "running"):
            terminate_state(state)
        if rec.pg_oid and db_oid(rec.name) == rec.pg_oid:
            lock = DbLock(rec.name)
            if lock.acquire():
                try:
                    dbcompat.drop_drill(rec.name)
                finally:
                    lock.release()
            else:
                log.warning("salvor_connector: drill %s busy, not dropped on uninstall", rec.name)
    root = jobs_root(dbname)
    drills = os.path.join(os.path.dirname(os.path.dirname(root)), "drills", dbname)
    for base in (root, drills):
        if os.path.isdir(base):
            for name in os.listdir(base):
                state = read_state(os.path.join(base, name))
                if state.get("state") in ("starting", "running"):
                    terminate_state(state)
        shutil.rmtree(base, ignore_errors=True)
