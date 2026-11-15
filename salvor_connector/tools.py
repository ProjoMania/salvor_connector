"""Helpers shared by the model and the controller (no ORM state here)."""
import fcntl
import hashlib
import ipaddress
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import zipfile

from odoo.tools import config
from odoo.tools.misc import exec_pg_environ, find_pg_tool

# info.protocol stays 1 (the baseline every deployed Salvor accepts); v2 is
# advertised through PROTOCOLS_SUPPORTED + CAPABILITIES. v1 endpoints stay served.
PROTOCOL_VERSION = 1
PROTOCOLS_SUPPORTED = [1, 2]
# No drill capability: the connector has no restore code (removed in 2.0.4).
CAPABILITIES = ["backup_job", "range_download", "audit_log", "drill_cleanup"]
JOB_TTL_HOURS_DEFAULT = 6
BACKUP_DISK_MARGIN = 256 * 1024 * 1024
JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
DRILL_RE = re.compile(r"^salvor_drill_[a-z0-9_]{1,40}$")
# PostgreSQL identifiers Odoo accepts as db names (same charset as odoo.service.db).
DBNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
CHUNK = 64 * 1024


def sha256_hex(value):
    return hashlib.sha256(value.encode()).hexdigest()


def parse_ips(text):
    """Return a list of ip_network objects from a comma/whitespace separated text."""
    nets = []
    for item in re.split(r"[\s,;]+", text or ""):
        if item:
            try:
                nets.append(ipaddress.ip_network(item.strip(), strict=False))
            except ValueError:
                continue
    return nets


def ip_allowed(addr, allowed_text):
    try:
        ip = ipaddress.ip_address((addr or "").strip())
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in net for net in parse_ips(allowed_text))


def lock_dir():
    return os.path.join(config["data_dir"], "salvor_connector", "locks")


class DbLock:
    """Cross-process (prefork-safe) non-blocking per-db lock using flock."""

    def __init__(self, dbname):
        if not DBNAME_RE.match(dbname):
            raise ValueError("bad db name")
        os.makedirs(lock_dir(), mode=0o700, exist_ok=True)
        self.path = os.path.join(lock_dir(), dbname + ".lock")
        self.fd = None

    def acquire(self):
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self.fd = fd
        return True

    def detach(self):
        """Hand the held lock to a child that inherited ``self.fd``: close our
        copy WITHOUT unlocking (flock belongs to the shared open file
        description, so the child's copy keeps it until the child exits)."""
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def release(self):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None


def stream_pg_dump(dbname):
    """Yield `pg_dump -Fc` output chunks; raise at the end if pg_dump failed."""
    cmd = [find_pg_tool("pg_dump"), "--no-owner", "--format=c", "--dbname=" + dbname]
    proc = subprocess.Popen(cmd, env=exec_pg_environ(), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        while True:
            chunk = proc.stdout.read(CHUNK)
            if not chunk:
                break
            yield chunk
        if proc.wait() != 0:
            raise RuntimeError("pg_dump failed with code %s" % proc.returncode)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()


class _QueueWriter:
    """Unseekable file-like object feeding a bounded queue (back-pressure)."""

    def __init__(self, q):
        self.q = q
        self.closed_by_reader = threading.Event()

    def write(self, data):
        if self.closed_by_reader.is_set():
            raise BrokenPipeError("reader gone")
        if data:
            data = bytes(data)
            while True:
                try:
                    self.q.put(data, timeout=1)
                    break
                except queue.Full:
                    if self.closed_by_reader.is_set():
                        raise BrokenPipeError("reader gone")
        return len(data)

    def flush(self):
        pass


def stream_odoo_zip(dbname, manifest):
    """Yield an Odoo-format backup zip (dump.sql, filestore/, manifest.json).

    Same layout as ``odoo.modules.db.dump(db, stream, backup_format='zip')`` but written
    straight to the socket: pg_dump stdout is piped into the zip entry and the
    filestore files are read in place, so nothing is copied to a temp dir.
    """
    q = queue.Queue(maxsize=64)
    writer = _QueueWriter(q)
    done = object()
    errors = []

    def produce():
        try:
            with zipfile.ZipFile(writer, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                cmd = [find_pg_tool("pg_dump"), "--no-owner", "--dbname=" + dbname]
                proc = subprocess.Popen(cmd, env=exec_pg_environ(), stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                try:
                    info = zipfile.ZipInfo("dump.sql", date_time=time.localtime()[:6])
                    info.compress_type = zipfile.ZIP_DEFLATED
                    with zf.open(info, "w", force_zip64=True) as entry:
                        while True:
                            chunk = proc.stdout.read(CHUNK)
                            if not chunk:
                                break
                            entry.write(chunk)
                    if proc.wait() != 0:
                        raise RuntimeError("pg_dump failed with code %s" % proc.returncode)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
                    proc.stdout.close()
                filestore = config.filestore(dbname)
                if os.path.isdir(filestore):
                    for dirpath, dirnames, filenames in os.walk(filestore, followlinks=False):
                        dirnames.sort()
                        for fname in sorted(filenames):
                            path = os.path.join(dirpath, fname)
                            if os.path.islink(path) or not os.path.isfile(path):
                                continue
                            arc = "filestore/" + os.path.relpath(path, filestore).replace(os.sep, "/")
                            zf.write(path, arc)
                zf.writestr("manifest.json", json.dumps(manifest, indent=4))
        except BaseException as e:  # noqa: BLE001 - reported to the consumer
            errors.append(e)
        finally:
            while True:
                try:
                    q.put(done, timeout=1)
                    break
                except queue.Full:
                    if writer.closed_by_reader.is_set():
                        break

    thread = threading.Thread(target=produce, name="salvor-zip-%s" % dbname, daemon=True)
    thread.start()
    try:
        while True:
            item = q.get()
            if item is done:
                break
            yield item
        if errors:
            raise RuntimeError("zip backup failed: %s" % errors[0])
    finally:
        writer.closed_by_reader.set()
        # drain so the producer can exit promptly
        try:
            while True:
                q.get_nowait()
        except queue.Empty:
            pass
        thread.join(timeout=5)


# ---------------------------------------------------------------- v2 jobs
def _private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def jobs_root(dbname):
    if not DBNAME_RE.match(dbname):
        raise ValueError("bad db name")
    return os.path.join(config["data_dir"], "salvor_connector", "jobs", dbname)


def job_dir(dbname, job_id):
    if not JOB_ID_RE.match(job_id or ""):
        return None
    return os.path.join(jobs_root(dbname), job_id)


def drill_dir(dbname, name):
    if not DRILL_RE.match(name or ""):
        raise ValueError("bad drill name")
    return os.path.join(config["data_dir"], "salvor_connector", "drills", dbname, name)


def read_state(path):
    try:
        with open(os.path.join(path, "state.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def write_state(path, **values):
    state = read_state(path)
    state.update(values)
    tmp = os.path.join(path, "state.json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, os.path.join(path, "state.json"))
    return state


def pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # a zombie child of this worker counts as dead
    try:
        with open("/proc/%d/stat" % int(pid), encoding="ascii") as fh:
            return fh.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return True


def live_state(path):
    """state.json, with a 'running' job whose process vanished reported failed."""
    state = read_state(path)
    if state.get("state") in ("starting", "running") and not pid_alive(state.get("pid")):
        started = state.get("spawned_at") or 0
        if time.time() - started > 30:  # give a just-spawned runner time to write its pid
            state = write_state(path, state="failed", error="job process exited unexpectedly")
    return state


def spawn_runner(path, spec, lock=None):
    """Write job.json and start jobrunner.py detached (own session).

    The child inherits the held per-db flock and keeps it until it exits; the
    caller's copy is closed without unlocking. A reaper thread waits on the
    child while this worker lives (no zombie); if the worker is recycled first,
    init adopts and reaps it.
    """
    fd = os.open(os.path.join(path, "job.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(spec, fh)
    write_state(path, state="starting", spawned_at=time.time(), kind=spec["kind"])
    runner = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jobrunner.py")
    args = [sys.executable, "-I", runner, path]
    pass_fds = ()
    if lock is not None and lock.fd is not None:
        args.append(str(lock.fd))
        pass_fds = (lock.fd,)
    proc = subprocess.Popen(args, cwd=path, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True, pass_fds=pass_fds,
                            env=_runner_env())
    write_state(path, pid=proc.pid, pid_start=proc_start_time(proc.pid))
    if lock is not None:
        lock.detach()

    def reap():
        try:
            proc.wait()
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=reap, name="salvor-reap-%s" % proc.pid, daemon=True).start()
    return proc.pid


def _runner_env():
    keep = ("PATH", "LANG", "LC_ALL", "TMPDIR", "HOME", "TZ")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.update(exec_pg_environ())
    return env


def disk_free(path):
    os.makedirs(path, exist_ok=True)
    return shutil.disk_usage(path).free


def remove_tree(path):
    shutil.rmtree(path, ignore_errors=True)


def trim_jobs(dbname, keep):
    """Keep at most `keep` finished backup jobs of this database (newest first):
    with one running job (the per-db lock) this bounds the disk a token holder
    can fill to keep + 1 archives."""
    root = jobs_root(dbname)
    if not os.path.isdir(root):
        return 0
    jobs = []
    for job_id in os.listdir(root):
        path = os.path.join(root, job_id)
        if JOB_ID_RE.match(job_id) and os.path.isdir(path):
            state = read_state(path)
            if state.get("state") in ("starting", "running") and pid_alive(state.get("pid")):
                continue
            jobs.append((state.get("spawned_at") or os.path.getmtime(path), path))
    jobs.sort(reverse=True)
    for _ts, path in jobs[keep:]:
        remove_tree(path)
    return max(len(jobs) - keep, 0)


def sweep_drill_files(dbname):
    """Delete this database's drill upload directories (Disconnect, after the
    owned drill databases were dropped); a runner still alive is stopped first."""
    base = os.path.join(config["data_dir"], "salvor_connector", "drills", dbname)
    if not os.path.isdir(base):
        return
    for name in os.listdir(base):
        state = read_state(os.path.join(base, name))
        if state.get("state") in ("starting", "running"):
            terminate_state(state)
    shutil.rmtree(base, ignore_errors=True)


def sweep_jobs(dbname, ttl_hours):
    """Delete this database's backup jobs older than ttl_hours (finished or
    not: a runner still alive after 2x ttl is terminated first)."""
    root = jobs_root(dbname)
    if not os.path.isdir(root):
        return 0
    removed = 0
    now = time.time()
    for job_id in os.listdir(root):
        path = os.path.join(root, job_id)
        if not JOB_ID_RE.match(job_id) or not os.path.isdir(path):
            continue
        state = read_state(path)
        age = now - (state.get("spawned_at") or os.path.getmtime(path))
        if age < ttl_hours * 3600:
            continue
        if state.get("state") in ("starting", "running") and pid_alive(state.get("pid")):
            if age < 2 * ttl_hours * 3600:
                continue
            terminate_state(state)
        remove_tree(path)
        removed += 1
    return removed


def proc_start_time(pid):
    """Kernel start time of a process (/proc/<pid>/stat field 22), or None."""
    try:
        with open("/proc/%d/stat" % int(pid), encoding="ascii") as fh:
            return int(fh.read().rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def is_our_runner(pid, pid_start):
    """True only if pid is still the jobrunner we started (same start time and
    command line) — a recycled pid is never signalled."""
    if not pid or not pid_start or proc_start_time(pid) != pid_start:
        return False
    try:
        with open("/proc/%d/cmdline" % int(pid), "rb") as fh:
            return b"jobrunner.py" in fh.read()
    except OSError:
        return False


def terminate(pid, timeout=30, pid_start=None):
    """Stop a runner (its whole session) — only after verifying it is ours."""
    if not is_our_runner(pid, pid_start):
        return
    try:
        os.killpg(int(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.time() + timeout
    while time.time() < deadline and pid_alive(pid):
        time.sleep(0.2)
    if pid_alive(pid) and is_our_runner(pid, pid_start):
        try:
            os.killpg(int(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def terminate_state(state):
    terminate(state.get("pid"), pid_start=state.get("pid_start"))


_RANGE_RE = re.compile(r"^bytes=(\d*)-(\d*)$")


def parse_range(header, size):
    """Single byte range -> (start, end_inclusive), None for no header, or
    raise ValueError (416)."""
    if not header:
        return None
    m = _RANGE_RE.match(header.strip())
    if not m or (not m.group(1) and not m.group(2)):
        raise ValueError("unsupported range")
    if m.group(1):
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else size - 1
    else:  # suffix range: last N bytes
        n = int(m.group(2))
        start, end = max(size - n, 0), size - 1
    end = min(end, size - 1)
    if start >= size or start > end:
        raise ValueError("range not satisfiable")
    return start, end


def iter_file(path, start, length):
    with open(path, "rb") as fh:
        fh.seek(start)
        left = length
        while left > 0:
            chunk = fh.read(min(CHUNK * 16, left))
            if not chunk:
                break
            left -= len(chunk)
            yield chunk


def system_db():
    return config.get("db_system") or "postgres"


def db_oid(name):
    """pg_database.oid of name (as text), or None if it does not exist."""
    from contextlib import closing

    import odoo

    with closing(odoo.sql_db.db_connect(system_db()).cursor()) as cr:
        cr.execute("SELECT oid FROM pg_database WHERE datname = %s", (name,))
        row = cr.fetchone()
        return str(row[0]) if row else None
