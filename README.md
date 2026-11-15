# Salvor Connector (Odoo addon)

Free LGPL-3 addon that lets [Salvor](https://salvorcloud.com) back up one Odoo database without the
master password, with `list_db = False`, a `dbfilter`, or behind a reverse proxy.
Protocol: Salvor Connector protocol **v2** (`info` reports `protocol: 1` for older Salvor workers and
`protocols: [1, 2]`; the v1 `backup` stream is still served, the v1 `restore` route was removed in 2.0.1) —
`docs/CONNECTOR-PROTOCOL.md` in the Salvor repo.

Branches: `17.0`, `18.0`, `19.0`, `20.0`. **Linux only** (the background job uses `setsid`, `flock` and
`/proc`); Odoo on Windows or macOS is not supported.

## Install
1. Add this repository to `addons_path`, update the apps list, install **Salvor Connector**.
2. Settings → Salvor Connector → Settings (no developer mode needed; administrators only).
3. Paste the pairing code from Salvor (Add database → Connector) and click **Connect**.

## Endpoints (`POST /salvor/v1/<name>`)
| Endpoint | Body | Result |
|---|---|---|
| `info` | – | JSON: `protocol: 1`, `protocols: [1, 2]`, `capabilities`, versions, sizes, drill flag, free disk |
| `backup/start` | `{"format": "dump"\|"zip"}` | 202 `{job_id}`; the dump runs in a detached process |
| `backup/status` | `{"job_id"}` | `{state, bytes, sha256 (when done), error}` |
| `backup/download` | `{"job_id"}` (+ `Range`) | the archive, 200 or 206 (resumable) |
| `backup/cleanup` | `{"job_id"}` | deletes the job file (otherwise removed by the hourly housekeeping once 6 h old) |
| `drill/start` · `drill/upload` · `drill/restore` · `drill/status` | see protocol | drills only: claim, chunked upload, restore + neutralize, poll |
| `drop` | `{"name"}` | drills only: drops a drill db **this database created** |
| `backup` | v1 | streamed backup in one request, kept for older Salvor workers |
| `restore` | v1 | **removed in 2.0.1**: answers 410 `gone` |

Required headers: `Authorization: Bearer <token>`, `X-Salvor-Db: <db>`.
Odoo must route the request to a database before the module code runs: send `X-Odoo-Database: <db>`
too (Odoo 19+), or ensure the URL resolves to the database (single db, per-host `dbfilter`).

Errors: `{"error", "message"}` with 401 `unauthorized` — the connector's own answer is identical
for an unknown database, a database without the module, not paired, or a wrong token. Odoo itself
can still reveal whether a database exists (on 19+ through the status code it returns for an
`X-Odoo-Database` header, and response timing differs), as it does for any page: restrict
`/salvor/` to Salvor's IPs at nginx or the firewall if that matters to you — 403 (IP, disabled, drills off),
404 (db, job, or a drill this db does not own), 409 (busy / conflict), 410 (removed route), 416 (range),
422 (bad arguments), 507 (not enough disk).

## Security
- Only `sha256(token)` is stored; compared with `hmac.compare_digest`. Tokens never logged.
- Source IP allowlist (IP or CIDR); empty list refuses everything, checked after the token.
  **With `proxy_mode` on, the allowlist trusts the right-most `X-Forwarded-For` entry** — only safe
  if Odoo's own port is not reachable except through your proxy: bind Odoo to localhost
  (`http_interface = 127.0.0.1`) or firewall it. The token is required either way.
- **Copies unpair themselves:** the module ships `data/neutralize.sql`, so a database duplicated or
  restored with Odoo's *neutralize* option (or `odoo-bin neutralize`) loses the token hash, allow
  list and enabled flag. A plain copy without neutralization keeps the pairing — disconnect it.
- One backup/restore at a time per database (`flock` in `data_dir`, works across prefork workers;
  the detached job holds it until it exits).
- **Rotate token**: get a rotation code in Salvor, paste it, click *Rotate token* — the old token
  stops working in the same write. **Disconnect** revokes Salvor's access immediately.
- **Pull Log** (Settings → Salvor Connector → Pull Log, administrators only): time, endpoint, status,
  source IP, job and bytes of each `info`, backup start, download range, cleanup, drill step, drop and
  refusal, and the end of each backup job. Status polls (`backup/status`, `drill/status`) are not
  logged one by one. Kept 90 days
  (system parameter `salvor_connector.log_retention_days`). Refusals are rate-limited (30 rows per
  minute per database, counted in the database, all workers together), kept 14 days, and the table
  is capped at 200,000 rows.
- Drills are off by default. A drill database is created with an atomic `CREATE DATABASE`
  (an existing name is refused, never taken over), recorded as owned by this database
  (*Drill Databases* menu), restored only from the archive whose sha256 Salvor committed to, and
  **neutralized in the same transaction as the restore** (every installed module's
  `neutralize.sql`: crons and outgoing mail off; Salvor pairing cleared; new database uuid), so no
  cron thread ever sees it active, and only drill databases this database
  created can be dropped. Names must match `^salvor_drill_[a-z0-9_]{1,40}$`; never the live db.
- **What a drill archive may contain:** the archive's SQL is run by `psql` (`-X`, no psqlrc, a minimal
  environment). psql also runs backslash meta-commands (`\!` shell, `\connect`, `\o`, `\copy ... program`),
  so every line is checked before psql sees it: outside quoted strings, dollar-quoted bodies and
  `COPY ... FROM stdin` data, any backslash command except pg_dump's own `\restrict`/`\unrestrict` pair
  fails the drill with "unsafe archive". A plain string literal or a comment containing a backslash, and
  any `COPY` other than pg_dump's `COPY <table> (...) FROM stdin;`, are refused too. A backup made by
  `pg_dump` passes. The SQL itself still runs with the Odoo role's rights, inside the drill database.
- A drill database is a full copy, logins included, reachable like any database while it exists (unless
  a `dbfilter`/`db_name` excludes `salvor_drill_*`). Salvor drops it right after the check; one older than
  24 h (`salvor_connector.drill_ttl_hours`) is dropped by the hourly housekeeping, **Disconnect** drops
  them all, and *Drill Databases* has a **Drop** button.
- Drills refuse to start unless the Odoo `data_dir` has at least **2.5 × the archive size** free.
- No endpoint lists databases. The only outbound call is the HTTPS pairing POST.

## Requirements
- `list_db` is **never** needed or changed — leave the database manager off.
- The connector serves only databases Odoo itself lists: with `--database`/`db_name` and no
  `dbfilter`, those names; otherwise databases **owned by the Odoo PostgreSQL role**. A database
  restored by hand as `postgres` answers 401 until `ALTER DATABASE <db> OWNER TO <odoo role>`.
- **Uninstall** stops this database's jobs, deletes its job and drill files and drops the drill
  databases it created (if still the same database, by oid). A drill that is busy at that moment
  is left and logged — drop it by hand.
- Drills need the Odoo PostgreSQL role to have **`CREATEDB`** (`ALTER ROLE odoo CREATEDB;`), the
  same privilege Odoo's own database manager uses. Backups need nothing extra.
- Backups write a temporary archive (0600, owner-only) under
  `<data_dir>/salvor_connector/jobs/<db>/`: keep free space ≥ database size (+ filestore for zip).
  The file is **not encrypted**: it exists from the start of the dump until Salvor's download
  finishes and it calls `cleanup` (normally minutes); if Salvor never collects it, the hourly
  housekeeping deletes it once it is 6 hours old (an hourly sweep, so up to ~7 h; `salvor_connector.job_ttl_hours`),
  and a dump still running at 12 h is stopped and deleted. Uninstall and Disconnect delete it too.

## Why the dump runs as a detached process
The dump is started with Odoo's own Python as a separate process in its own session, outside the
worker that received the request. An in-worker thread dies when prefork recycles or kills the worker
(`limit_time_real`, memory limits) — measured: the in-request v1 stream was cut at 30 s. The process
is still bounded: one per database (flock), stopped by `cleanup`, by uninstall, or after 2 × the
job TTL; it imports nothing from Odoo and only runs `pg_dump` and reads the filestore.

## Operational notes
- Neither `limit_time_real` nor `limit_time_cpu` limits backups any more: the dump runs outside any HTTP request and Salvor
  downloads it in 256 MiB ranges, each a short request. (Measured: a 2.6 GB zip with
  `--workers=2 --limit-time-real=30 --limit-time-cpu=20` completed in 76 s; the v1 streamed
  endpoint was cut at 30 s.) Both limits still apply to the legacy v1 `backup`
  endpoint used by older Salvor workers; v2 makes them irrelevant, so no limit needs raising.
- Revocation is checked on every request (each download range is a request) and, for a legacy v1
  stream, every 30 s while it runs; *Disconnect* also stops a running backup job and deletes its file.
- nginx: no special timeouts are needed for v2. Keep `client_max_body_size` ≥ 257m on
  `/salvor/` for drill uploads (64 MiB chunks from Salvor, 256 MiB accepted) and do not buffer
  `/salvor/v1/backup` for v1 workers (`proxy_buffering off`; responses send `X-Accel-Buffering: no`).

## Tests
```
odoo-bin -d <throwaway> --addons-path=<odoo>/addons,<this repo> -i salvor_connector \
  --test-tags /salvor_connector --no-database-list --stop-after-init --http-port=<free port>
```
