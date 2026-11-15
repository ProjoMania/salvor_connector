# Salvor Connector (Odoo addon)

Free LGPL-3 addon that lets [Salvor](https://salvorcloud.com) back up one Odoo database without the
master password, with `list_db = False`, a `dbfilter`, or behind a reverse proxy.
Protocol: Salvor Connector protocol **v2** (`info` reports `protocol: 1` for older Salvor workers and
`protocols: [1, 2]`; the v1 `backup` stream is still served, the v1 `restore` route was removed in 2.0.1) —
`docs/CONNECTOR-PROTOCOL.md` in the Salvor repo.

> **Restore drills through the connector are disabled in this version (2.0.2); Salvor verifies backups
> on its own side.** Restoring an archive as the database role that owns production cannot be made safe
> by filtering the archive, so 2.0.0/2.0.1's drill endpoints answer 410 `drills_disabled` and the switch
> is gone. Upgrade from 2.0.0/2.0.1 now: the hourly housekeeping, *Disconnect*, the `drop` call and the
> *Drop* buttons still remove drill databases those versions created.

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
| `drill/start` · `drill/upload` · `drill/restore` · `drill/status` | – | **disabled in 2.0.2**: 410 `drills_disabled` |
| `drop` | `{"name"}` | drops a leftover drill db **this database created** (by oid) |
| `backup` | v1 | streamed backup in one request, kept for older Salvor workers |
| `restore` | v1 | 410 `drills_disabled` |

Required headers: `Authorization: Bearer <token>`, `X-Salvor-Db: <db>`.
Odoo must route the request to a database before the module code runs: send `X-Odoo-Database: <db>`
too (Odoo 19+), or ensure the URL resolves to the database (single db, per-host `dbfilter`).

Errors: `{"error", "message"}` with 401 `unauthorized` — the connector's own answer is identical
for an unknown database, a database without the module, not paired, or a wrong token. Odoo itself
can still reveal whether a database exists (on 19+ through the status code it returns for an
`X-Odoo-Database` header, and response timing differs), as it does for any page: restrict
`/salvor/` to Salvor's IPs at nginx or the firewall if that matters to you — 403 (IP, disabled, drills off),
404 (db, job, or a drill this db does not own), 409 (busy / conflict), 410 (drills disabled), 416 (range),
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
  stops working in the same write. **Disconnect** revokes Salvor's access immediately, clears the allowed IPs and the drill switch, stops a
  running backup or drill restore, deletes their files and drops the drill databases this database created.
- **Pull Log** (Settings → Salvor Connector → Pull Log, administrators only): time, endpoint, status,
  source IP, job and bytes of each `info`, backup start, download range, cleanup, drill step, drop and
  refusal, and the end of each backup job. Status polls (`backup/status`, `drill/status`) are not
  logged one by one. Kept 90 days
  (system parameter `salvor_connector.log_retention_days`). Refusals are rate-limited (30 rows per
  minute per database, counted in the database, all workers together), kept 14 days, and the table
  is capped at 200,000 rows; at the cap refusals are evicted first, so a flood of refused calls never
  pushes out the history of successful ones.
- Drill databases left by 2.0.0/2.0.1 (named `salvor_drill_*`, recorded with their oid under *Drill
  Databases*) are full copies of production, logins included: the hourly housekeeping drops those older
  than 24 h (`salvor_connector.drill_ttl_hours`), *Disconnect* drops them all, and both the list and the
  settings form have a **Drop** button. A database of that name the connector did not create is never
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
