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
import re
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


def psql_env(env, home):
    """Only what libpq needs: no PSQLRC / PAGER / PSQL_EDITOR / PGOPTIONS from
    the Odoo service environment reaches the psql that reads the archive."""
    keep = {k: v for k, v in env.items() if k.startswith("PG") and k not in ("PGOPTIONS",)}
    keep.update(PATH="/usr/local/bin:/usr/bin:/bin", HOME=home, LC_ALL="C",
                PSQLRC=os.devnull, PSQL_HISTORY=os.devnull)
    return keep


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


# Session settings a newer pg_dump writes that older servers reject (name -> first
# server version that knows it). Only the dump's SET preamble is filtered.
NEWER_SETTINGS = {b"transaction_timeout": 170000}
PREAMBLE_BYTES = 256 * 1024


def server_version_num(spec, dbname):
    cnx = _connect(spec, dbname)
    try:
        with cnx.cursor() as cr:
            cr.execute("SHOW server_version_num")
            return int(cr.fetchone()[0])
    finally:
        cnx.close()


def unsupported_settings(version):
    return {name for name, since in NEWER_SETTINGS.items() if version < since}


_PREAMBLE_PREFIXES = (b"SET ", b"SELECT pg_catalog.set_config", b"\\restrict", b"--")


def _is_preamble(line):
    stripped = line.strip()
    return not stripped or stripped.startswith(_PREAMBLE_PREFIXES)


def filter_preamble(chunks, drop):
    r"""Drop `SET <name> = ...;` lines for settings the target server does not
    know — only in pg_dump's leading preamble (SET / set_config / \restrict /
    comments / blank lines). Filtering stops at the first other line and
    everything after it (DDL, COPY data) passes through byte for byte, so
    ON_ERROR_STOP still catches every real error."""
    if not drop:
        yield from chunks
        return
    buf = b""
    for chunk in chunks:
        buf += chunk
        out = []
        while True:
            nl = buf.find(b"\n")
            if nl < 0:
                if len(buf) > PREAMBLE_BYTES:  # no newline for that long: not a preamble
                    yield b"".join(out) + buf
                    yield from chunks
                    return
                break
            line, buf = buf[:nl + 1], buf[nl + 1:]
            if not _is_preamble(line):
                yield b"".join(out) + line + buf
                yield from chunks
                return
            if not any(line.startswith(b"SET " + n + b" ") or line.startswith(b"SET " + n + b"=")
                       for n in drop):
                out.append(line)
        if out:
            yield b"".join(out)
    if buf:
        yield buf


class UnsafeArchive(RuntimeError):
    pass


_IDENT = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")
_DOLLAR_RE = re.compile(rb"\$([A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)?\$")
_RESTRICT_RE = re.compile(rb"\\(restrict|unrestrict) ([A-Za-z0-9]{1,128})\r?\n?\Z")
# the only COPY form pg_dump / pg_restore write; any other COPY is refused
_COPY_IN_RE = re.compile(rb"\s*COPY\s+[\w.\"$\x80-\xff]+(\s*\([^()]*\))?\s+FROM\s+stdin\s*\Z", re.I)
_COPY_RE = re.compile(rb"\s*COPY\b", re.I)


class PsqlGuard:
    r"""Line-based gate in front of psql. psql runs backslash meta-commands
    (\! shell, \c, \o, \copy ... program, \set ON_ERROR_STOP) found anywhere in
    its input outside quotes and COPY data; a pg_dump archive never contains
    one, so any such line aborts the restore before psql sees it.

    The lexer tracks what psql tracks: '...' literals (a backslash right
    before a quote is refused there: it is the only place where E'' escapes
    or standard_conforming_strings, which the archive's SQL could switch,
    change where a literal ends, so every reading agrees), "...",
    $tag$...$tag$ (refused when glued to a preceding word or number),
    -- and nested /* */ comments, and
    COPY ... FROM stdin data up to the `\.` line. Allowed outside those: one
    `\restrict KEY` line and `\unrestrict` with the same key (pg_dump's own
    guard, which psql then enforces too). Unknown or unbalanced state at the
    end of the stream is refused, so nothing appended after it (the
    neutralization tail) can be swallowed into a string or COPY block."""

    MAX_LINE = 1024 * 1024 * 1024

    def __init__(self):
        self.mode = "sql"  # sql | sq | dq | dollar | block | copy
        self.tag = b""
        self.depth = 0
        self.stmt = bytearray()
        self.restrict_key = None
        self.restrict_used = False
        self.line_no = 0

    def _refuse(self, why):
        raise UnsafeArchive("unsafe archive: %s (line %d)" % (why, self.line_no))

    def feed(self, chunks):
        buf = b""
        for chunk in chunks:
            buf += chunk
            out = []
            start = 0
            while True:
                nl = buf.find(b"\n", start)
                if nl < 0:
                    break
                line = buf[start:nl + 1]
                self.check_line(line)
                out.append(line)
                start = nl + 1
            buf = buf[start:]
            if len(buf) > self.MAX_LINE:
                self._refuse("line too long")
            if out:
                yield b"".join(out)
        if buf:
            self.check_line(buf)
            yield buf
        self.finish()

    def finish(self):
        if self.mode != "sql":
            self._refuse("archive ends inside %s" % self.mode)
        if bytes(self.stmt).strip():
            self._refuse("archive ends inside a statement")

    def check_line(self, line):
        self.line_no += 1
        if b"\x00" in line:  # psql and the server stop reading a string at NUL: no common reading
            self._refuse("NUL byte")
        if self.mode == "copy":
            if line in (b"\\.\n", b"\\.\r\n", b"\\."):
                self.mode = "sql"
            return
        if self.mode == "sql" and not bytes(self.stmt).strip() and line.startswith(b"\\"):
            m = _RESTRICT_RE.match(line)
            if m and m.group(1) == b"restrict" and not self.restrict_used:
                self.restrict_used, self.restrict_key = True, m.group(2)
                return
            if m and m.group(1) == b"unrestrict" and self.restrict_key == m.group(2):
                self.restrict_key = None
                return
            self._refuse("psql meta-command")
        i, n = 0, len(line)
        while i < n:
            c = line[i]
            mode = self.mode
            if mode == "sql":
                if c == 0x5C:  # backslash
                    self._refuse("psql meta-command")
                if c == 0x2D and line[i + 1:i + 2] == b"-":  # -- comment: psql ends it at \r or \n
                    self.stmt += b" "
                    cr = line.find(b"\r", i)
                    if cr < 0:
                        break
                    i = cr + 1
                    continue
                if c == 0x2F and line[i + 1:i + 2] == b"*":
                    self.mode, self.depth = "block", 1
                    i += 2
                    continue
                prev = line[i - 1] if i else 0x20
                ident_before = prev in _IDENT or prev >= 0x80
                if c == 0x27:  # ' (plain, E'', U&'', B'', X'' alike: see sq below)
                    self.mode = "sq"
                    self.stmt += b"'s'"
                elif c == 0x22:
                    self.mode = "dq"
                    self.stmt += b'"i"'
                elif c == 0x24:
                    m = _DOLLAR_RE.match(line, i)
                    if m and ident_before:
                        # `x$a$` is an identifier, `1$a$` a number then a dollar quote:
                        # psql's reading depends on the token, so refuse the ambiguity
                        self._refuse("ambiguous dollar quote")
                    if m:
                        self.mode, self.tag = "dollar", m.group(0)
                        self.stmt += b"$d$"
                        i = m.end()
                        continue
                    self.stmt.append(c)
                elif c == 0x3B:  # ;
                    self._end_statement(line[i + 1:])
                else:
                    self.stmt.append(c)
                i += 1
            elif mode == "sq":
                if c == 0x5C and line[i + 1:i + 2] == b"'":
                    # the one sequence whose reading depends on standard_conforming_strings
                    self._refuse("backslash before a quote in a plain string literal")
                if c == 0x27:
                    if line[i + 1:i + 2] == b"'":
                        i += 2
                        continue
                    self.mode = "sql"
                i += 1
            elif mode == "dq":
                if c == 0x22:
                    if line[i + 1:i + 2] == b'"':
                        i += 2
                        continue
                    self.mode = "sql"
                i += 1
            elif mode == "dollar":
                end = line.find(self.tag, i)
                if end < 0:
                    break
                self.mode = "sql"
                i = end + len(self.tag)
            else:  # block comment
                if c == 0x2F and line[i + 1:i + 2] == b"*":
                    self.depth += 1
                    i += 2
                    continue
                if c == 0x2A and line[i + 1:i + 2] == b"/":
                    self.depth -= 1
                    i += 2
                    if not self.depth:
                        self.mode = "sql"
                        self.stmt += b" "  # a comment separates tokens: COPY/**/t is COPY t
                    continue
                i += 1

    def _end_statement(self, rest):
        stmt = bytes(self.stmt)
        self.stmt = bytearray()
        if _COPY_RE.match(stmt):
            if not _COPY_IN_RE.match(stmt):
                self._refuse("COPY statement not written by pg_dump")
            if rest.strip():
                self._refuse("text after COPY ... FROM stdin")
            self.mode = "copy"


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
                                 "--dbname=" + target], env=psql_env(env, tmp), stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, stderr=psql_err)
        src = None
        try:
            if source:
                src = subprocess.Popen(source, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=src_err)
                feed = src.stdout
            else:
                feed = open(sql_file, "rb")
            drop = unsupported_settings(server_version_num(spec, target))
            try:
                with feed:
                    guard = PsqlGuard()
                    raw = iter(lambda: feed.read(CHUNK), b"")
                    for chunk in guard.feed(filter_preamble(raw, drop)):
                        psql.stdin.write(chunk)
                psql.stdin.write(b"\n")
                psql.stdin.write(neutralize_tail(spec))
                psql.stdin.close()
            except BrokenPipeError:
                pass  # psql stopped on an error: its stderr (below) says which
            rc = psql.wait()
            psql_err.seek(0)
            err = psql_err.read()
            # psql first: when it stops on an error, pg_restore then dies of a broken pipe
            if rc != 0:
                raise RuntimeError("psql failed (code %s): %s" % (rc, err.decode(errors="replace")[-300:]))
            if src is not None and src.wait() != 0:
                src_err.seek(0)
                raise RuntimeError("pg_restore failed (code %s): %s" % (
                    src.returncode, src_err.read().decode(errors="replace")[-300:]))
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
