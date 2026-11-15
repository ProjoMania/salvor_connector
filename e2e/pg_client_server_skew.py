"""Restore a pg_dump-18 archive with jobrunner.run_restore into older servers (PG 14/15/16 in Docker,
ports 165NN, role odoo with CREATEDB, source db salvor_ws3_src installed on each). Usage:
  python e2e/pg_client_server_skew.py <workdir> 14 15 16"""
import json, os, subprocess, sys, tempfile, zipfile
sys.path.insert(0, os.environ.get("RUNNER_DIR", "/home/moh/Projects/salvor_connector/salvor_connector"))
import jobrunner  # stdlib + psycopg2 only

SRC = "salvor_ws3_src"
work = tempfile.mkdtemp(dir=sys.argv[1])
neut = {}
for base in ("/home/moh/OdooProjects/Odoo19/odoo/odoo/addons", "/home/moh/OdooProjects/Odoo19/odoo/addons"):
    for m in os.listdir(base):
        p = os.path.join(base, m, "data", "neutralize.sql")
        if os.path.isfile(p):
            neut.setdefault(m, p)
results = {}
for ver in sys.argv[2:]:
    env = {"PGHOST": "127.0.0.1", "PGPORT": "165" + ver, "PGUSER": "odoo", "PGPASSWORD": "ws3pw"}
    penv = {**os.environ, **env}
    dump = os.path.join(work, "a%s.dump" % ver)
    subprocess.run(["pg_dump", "--no-owner", "-Fc", "-d", SRC, "-f", dump], check=True, env=penv)
    sql = subprocess.run(["pg_dump", "--no-owner", "-d", SRC], check=True, capture_output=True, env=penv).stdout
    assert b"SET transaction_timeout" in sql, "client did not emit transaction_timeout"
    zpath = os.path.join(work, "a%s.zip" % ver)
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("dump.sql", sql)
        z.writestr("manifest.json", "{}")
    for kind, arch in (("dump", dump), ("zip", zpath)):
        target = "salvor_drill_x%s_%s_%s" % (os.environ.get("TAG", "n"), ver, kind)
        pass
        subprocess.run(["psql", "-q", "-d", "postgres", "-c", 'CREATE DATABASE "%s"' % target], env={**os.environ, **env}, check=True)
        jd = tempfile.mkdtemp(dir=work)
        subprocess.run(["cp", arch, os.path.join(jd, "archive")], check=True)
        spec = {"kind": "restore", "target": target, "pg_restore": "/usr/bin/pg_restore", "psql": "/usr/bin/psql",
                "filestore_dest": os.path.join(work, "fs_" + target), "neutralize_sql": neut, "pg_env": env}
        json.dump(spec, open(os.path.join(jd, "job.json"), "w"))
        job = jobrunner.Job(jd)
        try:
            jobrunner.run_restore(job)
            results[f"pg{ver}/{kind}"] = {"state": job.state["state"], **{k: job.state["neutralization"][k] for k in ("active_crons", "active_mail_servers", "pairing_left")}}
        except Exception as e:
            results[f"pg{ver}/{kind}"] = {"error": str(e)[:300]}
print(json.dumps(results, indent=1))
