# Salvor Connector (Odoo addon)

Free LGPL-3 addon that lets [Salvor](https://salvorcloud.com) back up one Odoo database without the
master password, with `list_db = False`, a `dbfilter`, or behind a reverse proxy or Cloudflare (see Requirements).
Protocol: Salvor Connector protocol **v2** (`info` reports `protocol: 1` for older Salvor workers and
`protocols: [1, 2]`; the v1 `backup` stream is still served; the v1 `restore` route answers 410 `drills_removed`) —
`docs/CONNECTOR-PROTOCOL.md` in the Salvor repo.

## Security advisory (SC-2026-01)
**Upgrade to the latest version** (2.0.4 or later fixes it). Restore drills through the connector could run `psql` meta-commands.
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
  security@salvorcloud.com. Advisories: [GHSA-qxmx-8p3v-m6x3](https://github.com/ProjoMania/salvor_connector/security/advisories/GHSA-qxmx-8p3v-m6x3)
  (restore drills) and [GHSA-28rv-398c-r5xx](https://github.com/ProjoMania/salvor_connector/security/advisories/GHSA-28rv-398c-r5xx) (chunked request bodies).

Support: **support@salvorcloud.com**.

Salvor checks each archive's integrity (sha256); restore drills need a master-password or SSH
connection. Leftover `salvor_drill_*` databases from 2.0.0/2.0.1 are still removed (see Security).

Branches: `16.0` (from 2.0.10), `17.0`, `18.0`, `19.0`, `20.0`. **Linux only** (the background job uses `setsid`, `flock` and
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

A 403 `ip_forbidden` (sent only to a caller that presented this database's token) also says what Odoo
saw, so that a proxy or Cloudflare setup can be fixed: `remote_addr` (the address that was checked against
Allowed IPs), `cloudflare` (that address is in Cloudflare's ranges), `via_cloudflare` (it was read from
`CF-Connecting-IP`) and `cloudflare_mode` (*Odoo is behind Cloudflare* is switched on). The allowlist
itself is never returned.

## Security
- Only `sha256(token)` is stored; compared with `hmac.compare_digest`. Tokens never logged.
- The access token is the protection: every route checks it first and refuses a request without it,
  whatever its address.
- Source IP allowlist (IP or CIDR), checked after the token; an empty list refuses everything. It checks
  the address Odoo sees for the request, so it is as good as your proxy setup and no better:
  - No proxy: the connecting address.
  - **With `proxy_mode` on, the right-most `X-Forwarded-For` entry.** That is the caller only if your proxy
    sets `X-Forwarded-For` itself and Odoo's own port cannot be reached except through the proxy: bind
    Odoo to localhost (`http_interface = 127.0.0.1`) or firewall it.
  - **Behind Cloudflare, only if you switch on *Odoo is behind Cloudflare*** (Settings → Salvor Connector →
    Settings; off by default): when the address above is in Cloudflare's ranges, the `CF-Connecting-IP`
    header is checked instead. The header is ignored from any other address, and on a request that carries
    a `CF-Worker` header (Cloudflare adds it to requests made by Workers): if a Worker of your own zone
    sits in front of Odoo, Salvor's calls are refused, and the Pull Log says "CF-Worker header present".
    With the switch off the header is never read, and a request that reaches Odoo from a Cloudflare
    address is refused. The switch works only where Cloudflare's own addresses connect to your server or
    proxy: through a Cloudflare Tunnel the request reaches Odoo from `cloudflared`, a local address, and
    the switch has no effect.
- **What the Cloudflare switch does not give you.** With the switch on, the allowlist does not protect
  against someone who already holds the access token. Cloudflare's ranges carry the traffic of every
  Cloudflare customer, so an address in those ranges does not show that a request came through *your*
  zone, or that your zone set its `CF-Connecting-IP` header.
  - Cloudflare's [HTTP headers reference](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
    says: "For Worker subrequests destined for a non-Cloudflare customer zone, the Worker script controls
    the client IP headers: both CF-Connecting-IP and x-real-ip can be altered by the Worker." The module
    refuses requests that carry `CF-Worker`.
  - The `CF-Worker` rule narrows one path. It does not make the header proof of who is calling: a request
    that did not come through your own zone can still arrive from Cloudflare's network with Salvor's
    address in it, with no Worker involved.
  - Restoring visitor addresses at your own proxy (nginx `real_ip_header CF-Connecting-IP` with
    `set_real_ip_from` Cloudflare's ranges) lets Salvor through with the switch off, but it relies on the
    same header from the same ranges and is open to the same.
  - What stops this is letting only your own zone reach Odoo: zone-level or per-hostname Authenticated
    Origin Pulls with your own certificate. (A Cloudflare Tunnel also does, but there the switch does not
    apply.) Without the token every request gets 401, whatever its address.
- Cloudflare's ranges are built into the module (Cloudflare's published list on 2026-11-20); nothing is
  fetched at run time. If Cloudflare changes them before a module release does, put the full list in the
  system parameter `salvor_connector.cloudflare_ranges` (comma-separated CIDRs, at most 256). An entry
  that is not a valid network, is broader than /8 (IPv4) or /16 (IPv6), is a loopback, private or
  link-local range, or is an IPv4-mapped IPv6 range makes the module ignore the parameter, use the
  built-in list and log a warning.
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
  pushes out the history of successful ones. *Last call* and the connection state on the settings form are
  read from this log (calls from Salvor never write the settings record), so the row of the latest
  successful call is kept past the 90 days until a newer one exists.
- Drill databases left by 2.0.0/2.0.1 (named `salvor_drill_*`, recorded with their oid) are full copies
  of production, logins included. While any exist the settings form shows a warning with a **Drop them
  now** button (administrators only); the hourly housekeeping drops them after 24 h
  (`salvor_connector.drill_ttl_hours`; 6 h if the upload or restore never finished, including a restore left running), and *Disconnect*
  and uninstall drop them too. A drill database busy at uninstall time is left and logged. A database of that name the connector did not create is never
  touched.
- No endpoint lists databases. The only outbound calls are the HTTPS pairing POST and, right after it, one
  HTTPS POST that asks Salvor to test the connection (`/api/connector/pair/check`: database name, Salvor
  instance number, the new access token as bearer).

## Requirements
- Odoo reachable over HTTPS from Salvor, with `web.base.url` set to its public `https://` address (the
  module sends it to Salvor at pairing; Salvor calls that address and does not follow redirects).
- Behind Cloudflare: switch on "Odoo is behind Cloudflare" in the module's settings (off by default), or
  restore visitor addresses at your own proxy. Both rely on Cloudflare's `CF-Connecting-IP` header, which
  does not show that a request came through your own zone: the access token is the protection (see
  Security). Not for Cloudflare Tunnel: there the switch has no effect.
- Behind your own reverse proxy: `proxy_mode = True`, and the proxy itself sets `X-Forwarded-For`,
  `X-Forwarded-Proto` and `X-Forwarded-Host`. Behind both, both apply. After pairing, the settings form
  shows the result of Salvor's connection test.
- `list_db` is **never** needed or changed — leave the database manager off.
- The connector serves only databases Odoo itself lists: with `--database`/`db_name` and no
  `dbfilter`, those names; otherwise databases **owned by the Odoo PostgreSQL role**. A database
  restored by hand as `postgres` answers 401 until `ALTER DATABASE <db> OWNER TO <odoo role>`.
- **Uninstall** deletes the module's system parameters (`salvor_connector.*`),
  stops this database's jobs, deletes its job and drill files and drops the drill
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
