"""Detached job runner for the Salvor Connector (protocol v2).

Backups only. 2.0.4 removed the restore half (drill restores through psql)
from the module entirely; the only external program this runner starts is
pg_dump.

Started by the controller as ``python jobrunner.py <job_dir> [lock_fd]`` in a
NEW SESSION (setsid), so it is not part of the Odoo worker's process group:
prefork recycling a worker (limit_memory_*, limit_request) or the master
killing it for limit_time_real does not kill the job.

It deliberately imports nothing from Odoo (only the standard library):
everything it needs — the pg_dump path, the
libpq environment, the filestore path, the manifest — is written into
``job.json`` by the controller. Progress and the result go to ``state.json``
(atomic replace), the archive to ``archive`` (0600). The per-database flock
taken by the controller is inherited as ``lock_fd`` and released when this
process exits.

Job kinds:
- ``backup``  : pg_dump -Fc, or an Odoo-format zip (dump.sql + filestore/ +
                manifest.json) written straight to ``archive`` with its sha256.
Any other kind (including the removed ``restore``) fails the job.
"""
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import zipfile

CHUNK = 1024 * 1024


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Job:
    def __init__(self, job_dir):
        self.dir = job_dir
        with open(os.path.join(job_dir, "job.json"), encoding="utf-8") as fh:
            self.spec = json.load(fh)
        self.state_path = os.path.join(job_dir, "state.json")
        self.archive = os.path.join(job_dir, "archive")
        self.state = {}
        if os.path.exists(self.state_path):
            with open(self.state_path, encoding="utf-8") as fh:
                self.state = json.load(fh)

    def write_state(self, **values):
        self.state.update(values)
        tmp = self.state_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh)
        os.replace(tmp, self.state_path)


class HashingWriter:
    """File-like sink that hashes and counts what it writes (zipfile needs
    write/tell/flush; seek is not offered so zipfile streams data descriptors)."""

    def __init__(self, fh):
        self.fh = fh
        self.sha = hashlib.sha256()
        self.size = 0

    def write(self, data):
        data = bytes(data)
        self.fh.write(data)
        self.sha.update(data)
        self.size += len(data)
        return len(data)

    def tell(self):
        return self.size

    def flush(self):
        self.fh.flush()


def _env(spec):
    env = dict(os.environ)
    env.update(spec.get("pg_env") or {})
    return env


def run_backup(job):
    spec = job.spec
    fd = os.open(job.archive, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as raw:
        out = HashingWriter(raw)
        if spec["format"] == "dump":
            cmd = [spec["pg_dump"], "--no-owner", "--format=c", "--dbname=" + spec["db"]]
            proc = subprocess.Popen(cmd, env=_env(spec), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for chunk in iter(lambda: proc.stdout.read(CHUNK), b""):
                out.write(chunk)
            err = proc.stderr.read()
            if proc.wait() != 0:
                raise RuntimeError("pg_dump failed (code %s): %s" % (
                    proc.returncode, err.decode(errors="replace")[-300:]))
        else:
            with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                cmd = [spec["pg_dump"], "--no-owner", "--dbname=" + spec["db"]]
                proc = subprocess.Popen(cmd, env=_env(spec), stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                info = zipfile.ZipInfo("dump.sql", date_time=time.localtime()[:6])
                info.compress_type = zipfile.ZIP_DEFLATED
                with zf.open(info, "w", force_zip64=True) as entry:
                    for chunk in iter(lambda: proc.stdout.read(CHUNK), b""):
                        entry.write(chunk)
                err = proc.stderr.read()
                if proc.wait() != 0:
                    raise RuntimeError("pg_dump failed (code %s): %s" % (
                        proc.returncode, err.decode(errors="replace")[-300:]))
                filestore = spec.get("filestore") or ""
                files = 0
                if filestore and os.path.isdir(filestore):
                    for dirpath, dirnames, filenames in os.walk(filestore, followlinks=False):
                        dirnames.sort()
                        for fname in sorted(filenames):
                            path = os.path.join(dirpath, fname)
                            if os.path.islink(path) or not os.path.isfile(path):
                                continue
                            arc = "filestore/" + os.path.relpath(path, filestore).replace(os.sep, "/")
                            zf.write(path, arc)
                            files += 1
                            if files % 200 == 0:
                                job.write_state(bytes=out.size)
                zf.writestr("manifest.json", json.dumps(spec.get("manifest") or {}, indent=4))
        raw.flush()
        os.fsync(raw.fileno())
    job.write_state(state="done", bytes=out.size, sha256=out.sha.hexdigest(), finished_at=_now())


def main(argv):
    job = Job(argv[1])
    lock_fd = int(argv[2]) if len(argv) > 2 else None  # kept open (= lock held) until exit

    def on_term(signum, frame):
        job.write_state(state="failed", error="job terminated (signal %s)" % signum, finished_at=_now())
        os._exit(1)

    signal.signal(signal.SIGTERM, on_term)
    job.write_state(state="running", pid=os.getpid(), started_at=job.state.get("started_at") or _now())
    try:
        if job.spec["kind"] == "backup":
            run_backup(job)
        else:
            raise RuntimeError("unknown job kind")
    except BaseException as e:  # noqa: BLE001 - reported through state.json
        job.write_state(state="failed", error=str(e)[:500] or e.__class__.__name__, finished_at=_now())
        return 1
    finally:
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
