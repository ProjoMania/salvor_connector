# Salvor Connector (Odoo addon)

Free LGPL-3 addon that lets [Salvor](https://salvorcloud.com) back up one Odoo database without the
master password, with `list_db = False`, a `dbfilter`, or behind a reverse proxy.
Protocol: Salvor Connector protocol **v2** (`info` reports `protocol: 1` for older Salvor workers and
`protocols: [1, 2]`; the v1 `backup` stream is still served; the v1 `restore` route answers 410 `drills_removed`) —
`docs/CONNECTOR-PROTOCOL.md` in the Salvor repo.

## Security advisory (SC-2026-01)
**Upgrade to 2.0.6** (2.0.4 or later fixes it). Restore drills through the connector could run `psql` meta-commands.
- **Affected:** 1.0.0 (`/salvor/v1/restore` pipes archive SQL through `psql` when the drill switch is on);
  2.0.0 (drill restore via `psql`, no meta-command guard); 2.0.1 (guard in place, failed review).
- **Preconditions:** a valid connector token, an allowed IP, and drills enabled (off by default).
- **Impact:** meta-commands such as `\!` could run OS commands as the Odoo service user, and `\c` could
  reach other databases.
- **Not affected:** 2.0.2 and 2.0.3: every drill route raises 410 before any work; the restore code is
  unreachable. **Fixed:** 2.0.4: the code is removed.
- **Action:** pull your branch, **restart Odoo**, then upgrade the module (`-u salvor_connector` or
  *Upgrade* in Apps). Until then keep *Allow restore drills* off. From 1.0.0, 2.0.0 or 2.0.1, pair
  again after the upgrade (Salvor refuses those versions). Details: `SECURITY.md`.
- **Report a vulnerability** privately: GitHub **Security → Report a vulnerability**, or email
  security@salvorcloud.com.

Salvor checks each archive's integrity (sha256); restore drills need a master-password or SSH
connection. Leftover `salvor_drill_*` databases from 2.0.0/2.0.1 are still removed (see Security).

Branches: `17.0`, `18.0`, `19.0`, `20.0`. **Linux only** (the background job uses `setsid`, `flock` and
`/proc`); Odoo on Windows or macOS is not supported.

## Install
1. Add this repository to `addons_path`, update the apps list, install **Salvor Connector**.
2. Settings → Salvor Connector → Settings (no developer mode needed; administrators only).
3. Paste the pairing code from Salvor (Add database → Connector) and click **Connect**.

## Endpoints (`POST /salvor/v1/<name>`)
| Endpoint | Body | Result |
|---|---|---|
| `info` | – | JSON: `protocol: 1`, `protocols: [1, 2]`, `capabilities` (`backup_job`, `range_download`, `audit_log`, `drill_cleanup`), versions, sizes, `drill_enabled: false` (constant), free disk |
| `backup/start` | `{"format": "dump"\|"zip"}` | 202 `{job_id}`; the dump runs in a detached process |
| `backup/status` | `{"job_id"}` | `{state, bytes, sha256 (when done), error}` |
| `backup/download` | `{"job_id"}` (+ `Range`) | the archive, 200 or 206 (resumable) |
| `backup/cleanup` | `{"job_id"}` | deletes the job file (otherwise removed by the hourly housekeeping once 6 h old) |
| `drill/start` · `drill/upload` · `drill/restore` · `drill/status` | – | **removed in 2.0.4**: after the usual token/IP/enabled checks, 410 `drills_removed`; body not read (any body over 1 KiB: 413) |
| `drop` | `{"name"}` | drops a leftover drill db **this database created** (by oid) |
| `backup` | v1 | streamed backup in one request, kept for older Salvor workers |
| `restore` | v1 | as the drill stubs: checks, then 410 `drills_removed` |

Required headers: `Authorization: Bearer <token>`, `X-Salvor-Db: <db>`.
Odoo must route the request to a database before the module code runs: send `X-Odoo-Database: <db>`
too (Odoo 19+), or ensure the URL resolves to the database (single db, per-host `dbfilter`).

Errors: `{"error", "message"}` with 401 `unauthorized` — the connector's own answer is identical
for an unknown database, a database without the module, not paired, or a wrong token. Odoo itself
can still reveal whether a database exists (on 19+ through the status code it returns for an
`X-Odoo-Database` header, and response timing differs), as it does for any page: restrict
`/salvor/` to Salvor's IPs at nginx or the firewall if that matters to you — 403 (IP, Connector disabled),
404 (db, job, or a drill this db does not own), 409 (busy / conflict), 410 (drills removed), 416 (range),
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
- One backup at a time per database, at most 2 stored (`flock` in `data_dir`, works across prefork workers;
  the detached job holds it until it exits).
- **Rotate token**: get a rotation code in Salvor, paste it, click *Rotate token* — the old token
  stops working in the same write. **Disconnect** revokes Salvor's access immediately, clears the allowed IPs, stops a running
  backup, deletes its file and drops leftover drill databases this database created.
- **Pull Log** (Settings → Salvor Connector → Pull Log, administrators only): time, endpoint, status,
  source IP, job and bytes of each `info`, backup start, download range, cleanup, `drop` and refusal
  (including refused drill calls), and the end of each backup job. Successful status polls are not
  logged one by one. Kept 90 days
  (system parameter `salvor_connector.log_retention_days`). Refusals are rate-limited (30 rows per
  minute per database, counted in the database, all workers together), kept 14 days, and the table
  is capped at 200,000 rows; at the cap refusals are evicted first, so a flood of refused calls never
  pushes out the history of successful ones.
- Drill databases left by 2.0.0/2.0.1 (named `salvor_drill_*`, recorded with their oid) are full copies
  of production, logins included. While any exist the settings form shows a warning with a **Drop them
  now** button (administrators only); the hourly housekeeping drops them after 24 h
  (`salvor_connector.drill_ttl_hours`; 6 h if the upload or restore never finished, including a restore left running), and *Disconnect*
  and uninstall drop them too. A drill database busy at uninstall time is left and logged. A database of that name the connector did not create is never
  touched.
- No endpoint lists databases. The only outbound call is the HTTPS pairing POST.

## Requirements
- `list_db` is **never** needed or changed — leave the database manager off.
- The connector serves only databases Odoo itself lists: with `--database`/`db_name` and no
  `dbfilter`, those names; otherwise databases **owned by the Odoo PostgreSQL role**. A database
  restored by hand as `postgres` answers 401 until `ALTER DATABASE <db> OWNER TO <odoo role>`.
- **Uninstall** stops this database's jobs, deletes its job and drill files and drops the drill
  databases it created (if still the same database, by oid). A drill that is busy at that moment
  is left and logged — drop it by hand.
- Backups write a temporary archive (0600, owner-only) under
  `<data_dir>/salvor_connector/jobs/<db>/`: keep free space ≥ database size (+ filestore for zip).
  The file is **not encrypted**: it exists from the start of the dump until Salvor's download
  finishes and it calls `cleanup` (normally minutes; at most 2 backup archives are kept per database, so a
  new job deletes all but the newest finished one); if Salvor never collects it, the hourly
  housekeeping deletes it once it is 6 hours old (an hourly sweep, so up to about 7 hours; `salvor_connector.job_ttl_hours`),
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
- nginx: no special timeouts are needed for v2. Do not buffer
  `/salvor/v1/backup` for v1 workers (`proxy_buffering off`; responses send `X-Accel-Buffering: no`).

## Tests
```
odoo-bin -d <throwaway> --addons-path=<odoo>/addons,<this repo> -i salvor_connector \
  --test-tags /salvor_connector --no-database-list --stop-after-init --http-port=<free port>
```
