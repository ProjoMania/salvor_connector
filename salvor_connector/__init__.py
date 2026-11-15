from . import models
from . import controllers

from .tools import lock_dir


def uninstall_hook(env):
    """Remove on-disk lock files; the config table itself is dropped by the ORM."""
    import shutil
    import os

    path = lock_dir()
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
    # this database's backup jobs and drill uploads go with the module
    from .tools import jobs_root, read_state, terminate
    for root in (jobs_root(env.cr.dbname),
                 os.path.join(os.path.dirname(os.path.dirname(jobs_root(env.cr.dbname))), "drills", env.cr.dbname)):
        if os.path.isdir(root):
            for name in os.listdir(root):
                state = read_state(os.path.join(root, name))
                if state.get("state") in ("starting", "running"):
                    terminate(state.get("pid"))
        shutil.rmtree(root, ignore_errors=True)
