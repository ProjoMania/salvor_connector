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
