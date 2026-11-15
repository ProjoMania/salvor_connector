"""Detached job runner for the Salvor Connector (protocol v2).

Started by the controller as ``python jobrunner.py <job_dir> [lock_fd]`` in a
NEW SESSION (setsid), so it is not part of the Odoo worker's process group:
prefork recycling a worker (limit_memory_*, limit_request) or the master
killing it for limit_time_real does not kill the job.

It deliberately imports nothing from Odoo (only the standard library and
psycopg2, which every Odoo has): everything it needs — pg tool paths, the
libpq environment, the filestore path, the manifest — is written into
``job.json`` by the controller. Progress and the result go to ``state.json``
(atomic replace), the archive to ``archive`` (0600). The per-database flock
taken by the controller is inherited as ``lock_fd`` and released when this
process exits.

Job kinds:
- ``backup``  : pg_dump -Fc, or an Odoo-format zip (dump.sql + filestore/ +
                manifest.json) written straight to ``archive`` with its sha256.
- ``restore`` : restore ``archive`` (pg_dump -Fc or Odoo zip) into the drill
                database the controller already created, move the filestore,
                then NEUTRALIZE it (Odoo's per-module data/neutralize.sql, the
                same files ``odoo.modules.neutralize`` runs) and give it a new
                database.uuid/secret, and record what is still active.
"""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
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


def _connect(spec, dbname):
    import psycopg2  # Odoo's own dependency; imported late so --help works anywhere

    for key, value in (spec.get("pg_env") or {}).items():
        os.environ[key] = value
    return psycopg2.connect(dbname=dbname)


def neutralize(spec, dbname):
    """Run every installed module's data/neutralize.sql (as odoo.modules.neutralize
    does), then a new database.uuid/secret (as restore_db(copy=True) does).
    Returns what is still active afterwards, for the drill record."""
    sql_files = spec.get("neutralize_sql") or {}
    cnx = _connect(spec, dbname)
    try:
        with cnx, cnx.cursor() as cr:
            cr.execute("SELECT name FROM ir_module_module WHERE state IN ('installed', 'to upgrade', 'to remove')")
            modules = [row[0] for row in cr.fetchall()]
            ran = []
            for module in modules:
                path = sql_files.get(module)
                if path and os.path.isfile(path):
                    with open(path, encoding="utf-8") as fh:
                        query = fh.read().strip()
                    if query:
                        cr.execute(query)
                        ran.append(module)
            # Belt and braces in case a module shipped no neutralize.sql for its own
            # outgoing channel: nothing in a drill may send mail or run scheduled work.
            cr.execute("""UPDATE ir_cron SET active = false WHERE active AND id NOT IN (
                            SELECT res_id FROM ir_model_data
                             WHERE model = 'ir.cron' AND module = 'base' AND name = 'autovacuum_job')""")
            cr.execute("UPDATE ir_mail_server SET active = false "
                       "WHERE active AND smtp_host != 'invalid'")
            cr.execute("SELECT to_regclass('fetchmail_server')")
            if cr.fetchone()[0]:
                cr.execute("UPDATE fetchmail_server SET active = false WHERE active")
            cr.execute("""SELECT count(*) FROM ir_cron WHERE active AND id NOT IN (
                            SELECT res_id FROM ir_model_data
                             WHERE model = 'ir.cron' AND module = 'base' AND name = 'autovacuum_job')""")
            crons = cr.fetchone()[0]
            cr.execute("SELECT count(*) FROM ir_mail_server WHERE active AND smtp_host != 'invalid'")
            mail = cr.fetchone()[0]
            pairing = 0
            cr.execute("SELECT to_regclass('salvor_connector_config')")
            if cr.fetchone()[0]:
                cr.execute("SELECT count(*) FROM salvor_connector_config WHERE token_hash IS NOT NULL OR enabled")
                pairing = cr.fetchone()[0]
            cr.execute("SELECT value FROM ir_config_parameter WHERE key = 'database.is_neutralized'")
            row = cr.fetchone()
            flag = bool(row and str(row[0]).lower() in ("true", "1"))
    finally:
        cnx.close()
    return {"modules_neutralized": ran, "active_crons": crons, "active_mail_servers": mail,
            "is_neutralized_flag": flag, "pairing_left": pairing}


def neutralize_tail(spec):
    """SQL appended to the restore stream so it commits in the SAME transaction
    as the data: no moment exists where the drill database has active crons,
    mail servers or Salvor pairing that a cron thread could pick up."""
    # pg_dump output ends with search_path = '' — tables must resolve again
    parts = ["SET search_path TO public, pg_catalog;"]
    for module, path in sorted((spec.get("neutralize_sql") or {}).items()):
        try:
            with open(path, encoding="utf-8") as fh:
                query = fh.read().strip()
        except OSError:
            continue
        if not query or "$salvor_q$" in query:
            continue
        mod = module.replace("'", "''")
        parts.append(
            "DO $salvor_do$ BEGIN IF EXISTS (SELECT 1 FROM ir_module_module WHERE name = '%s' "
            "AND state IN ('installed', 'to upgrade', 'to remove')) THEN EXECUTE $salvor_q$%s$salvor_q$; "
            "END IF; END $salvor_do$;" % (mod, query))
    parts.append("""
UPDATE ir_cron SET active = false WHERE active AND id NOT IN (
    SELECT res_id FROM ir_model_data WHERE model = 'ir.cron' AND module = 'base' AND name = 'autovacuum_job');
UPDATE ir_mail_server SET active = false WHERE active AND smtp_host != 'invalid';
DO $salvor_do$ BEGIN
  IF to_regclass('fetchmail_server') IS NOT NULL THEN
    UPDATE fetchmail_server SET active = false WHERE active;
  END IF;
  IF to_regclass('salvor_connector_config') IS NOT NULL THEN
    UPDATE salvor_connector_config SET token_hash = NULL, allowed_ips = NULL, paired_at = NULL,
           instance_id = NULL, enabled = false, drill_enabled = false;
  END IF;
END $salvor_do$;
UPDATE ir_config_parameter SET value = '%s' WHERE key = 'database.uuid';
UPDATE ir_config_parameter SET value = '%s' WHERE key = 'database.secret';
""" % (uuid.uuid1(), uuid.uuid4()))
    return "\n".join(parts).encode()


def run_restore(job):
    spec = job.spec
    target = spec["target"]
    env = _env(spec)
    with open(job.archive, "rb") as fh:
        magic = fh.read(5)
    job.write_state(phase="restoring")
    with tempfile.TemporaryDirectory(dir=job.dir) as tmp:
        filestore_src = None
        if magic == b"PGDMP":
            # pg_restore renders SQL; psql runs it + the neutralization as ONE transaction
            source = [spec["pg_restore"], "--no-owner", "-f", "-", job.archive]
            sql_file = None
        elif zipfile.is_zipfile(job.archive):
            with zipfile.ZipFile(job.archive) as z:
                names = z.namelist()
                if "dump.sql" not in names:
                    raise RuntimeError("zip has no dump.sql")
                members = ["dump.sql"] + [m for m in names if m.startswith("filestore/")
                                          and ".." not in m.split("/") and not m.startswith("/")]
                z.extractall(tmp, members)
            if any(m.startswith("filestore/") for m in members):
                filestore_src = os.path.join(tmp, "filestore")
            source = None
            sql_file = os.path.join(tmp, "dump.sql")
        else:
            raise RuntimeError("archive is neither a pg_dump custom dump nor an Odoo zip")
        psql_err = open(os.path.join(tmp, "psql.err"), "w+b")
        src_err = open(os.path.join(tmp, "src.err"), "w+b")
        psql = subprocess.Popen([spec["psql"], "-q", "-X", "-1", "-v", "ON_ERROR_STOP=1",
                                 "--dbname=" + target], env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, stderr=psql_err)
        src = None
        try:
            if source:
                src = subprocess.Popen(source, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=src_err)
                feed = src.stdout
            else:
                feed = open(sql_file, "rb")
            with feed:
                for chunk in iter(lambda: feed.read(CHUNK), b""):
                    psql.stdin.write(chunk)
            psql.stdin.write(b"\n")
            psql.stdin.write(neutralize_tail(spec))
            psql.stdin.close()
            rc = psql.wait()
            psql_err.seek(0)
            err = psql_err.read()
            if src is not None and src.wait() != 0:
                src_err.seek(0)
                raise RuntimeError("pg_restore failed (code %s): %s" % (
                    src.returncode, src_err.read().decode(errors="replace")[-300:]))
            if rc != 0:
                raise RuntimeError("psql failed (code %s): %s" % (rc, err.decode(errors="replace")[-300:]))
        finally:
            for proc in (src, psql):
                if proc is not None and proc.poll() is None:
                    proc.kill()
            psql_err.close()
            src_err.close()
        if filestore_src:
            dest = spec["filestore_dest"]
            if os.path.exists(dest):
                shutil.rmtree(dest)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.move(filestore_src, dest)
    job.write_state(phase="verifying")
    result = neutralize(spec, target)  # idempotent re-run + the counts we report
    if result["active_crons"] or result["active_mail_servers"] or result["pairing_left"]:
        raise RuntimeError("neutralization left %(active_crons)s cron(s), %(active_mail_servers)s "
                           "mail server(s), pairing=%(pairing_left)s" % result)
    try:
        os.unlink(job.archive)  # the drill db now holds the data; drop the copy early
    except OSError:
        pass
    job.write_state(state="done", phase="done", neutralization=result, finished_at=_now())


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
        elif job.spec["kind"] == "restore":
            run_restore(job)
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
