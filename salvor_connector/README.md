# Salvor Connector (Odoo addon)

Free LGPL-3 addon that lets [Salvor](https://salvorcloud.com) back up one Odoo database without the
master password, with `list_db = False`, a `dbfilter`, or behind a reverse proxy.
Protocol: Salvor Connector protocol **v2** (v1 endpoints still served) — `docs/CONNECTOR-PROTOCOL.md`
in the Salvor repo.

Branches: `20.0`, `19.0`, `18.0`, `17.0` (and `16.0`, unpublished, still v1).

## Install
1. Add this repository to `addons_path`, update the apps list, install **Salvor Connector**.
2. Developer mode → Settings → Technical → Salvor Connector → Settings.
3. Paste the pairing code from Salvor (Add database → Connector) and click **Connect**.

## Endpoints (`POST /salvor/v1/<name>`)
| Endpoint | Body | Result |
|---|---|---|
| `info` | – | JSON: protocol 2, `protocols`, `capabilities`, versions, sizes, drill flag, free disk |
| `backup/start` | `{"format": "dump"\|"zip"}` | 202 `{job_id}`; the dump runs in a detached process |
| `backup/status` | `{"job_id"}` | `{state, bytes, sha256 (when done), error}` |
| `backup/download` | `{"job_id"}` (+ `Range`) | the archive, 200 or 206 (resumable) |
| `backup/cleanup` | `{"job_id"}` | deletes the job file (auto-expiry after 24 h otherwise) |
| `drill/start` · `drill/upload` · `drill/restore` · `drill/status` | see protocol | drills only: claim, chunked upload, restore + neutralize, poll |
| `drop` | `{"name"}` | drills only: drops a drill db **this database created** |
| `backup`, `restore` | v1 | streamed backup / one-shot drill restore, kept for older Salvor workers |

Required headers: `Authorization: Bearer <token>`, `X-Salvor-Db: <db>`.
Odoo must route the request to a database before the module code runs: send `X-Odoo-Database: <db>`
too (Odoo 19+), or ensure the URL resolves to the database (single db, per-host `dbfilter`).

Errors: `{"error", "message"}` with 401 (token / not paired), 403 (IP, disabled, drills off),
404 (db, job, or a drill this db does not own), 409 (busy / conflict), 416 (range), 422 (bad
arguments), 507 (not enough disk).

## Security
- Only `sha256(token)` is stored; compared with `hmac.compare_digest`. Tokens never logged.
- Source IP allowlist (IP or CIDR); empty list refuses everything. `X-Forwarded-For` is used
  (right-most entry) only when Odoo runs with `proxy_mode`.
- One backup/restore at a time per database (`flock` in `data_dir`, works across prefork workers;
  the detached job holds it until it exits).
- **Rotate token**: get a rotation code in Salvor, paste it, click *Rotate token* — the old token
  stops working in the same write. **Disconnect** revokes Salvor's access immediately.
- **Pull Log** (Settings → Technical → Salvor Connector → Pull Log, administrators only): every
  call and every refusal with time, endpoint, status, source IP, job and bytes. Kept 90 days
  (system parameter `salvor_connector.log_retention_days`).
- Drills are off by default. A drill database is created with an atomic `CREATE DATABASE`
  (an existing name is refused, never taken over), recorded as owned by this database
  (*Drill Databases* menu), **neutralized** after restore (every module's `neutralize.sql`:
  crons and outgoing mail off; new database uuid), and only drill databases this database
  created can be dropped. Names must match `^salvor_drill_[a-z0-9_]{1,40}$`; never the live db.
- Drills refuse to start unless the Odoo `data_dir` has at least **2.5 × the archive size** free.
- No endpoint lists databases. The only outbound call is the HTTPS pairing POST.

## Requirements
- `list_db` is **never** needed or changed — leave the database manager off.
- Drills need the Odoo PostgreSQL role to have **`CREATEDB`** (`ALTER ROLE odoo CREATEDB;`), the
  same privilege Odoo's own database manager uses. Backups need nothing extra.
- Backups write a temporary archive (0600, owner-only) under
  `<data_dir>/salvor_connector/jobs/<db>/`: keep free space ≥ database size (+ filestore for zip).

## Operational notes
- `limit_time_real` no longer limits backups: the dump runs outside any HTTP request and Salvor
  downloads it in 256 MiB ranges, each a short request. (Measured: a 2.6 GB zip with
  `--workers=2 --limit-time-real=30` completed in 76 s; the v1 streamed endpoint was cut at 30 s.)
- nginx: no special timeouts are needed for v2. Keep `client_max_body_size` ≥ 257m on
  `/salvor/` for drill uploads (64 MiB chunks from Salvor, 256 MiB accepted) and do not buffer
  `/salvor/v1/backup` for v1 workers (`proxy_buffering off`; responses send `X-Accel-Buffering: no`).

## Tests
```
odoo-bin -d <throwaway> --addons-path=<odoo>/addons,<this repo> -i salvor_connector \
  --test-tags /salvor_connector --no-database-list --stop-after-init --http-port=<free port>
```
