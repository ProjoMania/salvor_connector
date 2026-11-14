"""Helpers shared by the model and the controller (no ORM state here)."""
import fcntl
import hashlib
import ipaddress
import json
import os
import queue
import re
import subprocess
import threading
import zipfile

from odoo.tools import config
from odoo.tools.misc import exec_pg_environ, find_pg_tool

PROTOCOL_VERSION = 1
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

    Same layout as ``odoo.service.db.dump_db(db, stream, 'zip')`` but written
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
                    with zf.open("dump.sql", "w", force_zip64=True) as entry:
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
