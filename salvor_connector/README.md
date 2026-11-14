# Salvor Connector (Odoo addon)

Free LGPL-3 addon that lets [Salvor](https://salvorcloud.com) back up one Odoo database without the
master password, with `list_db = False`, a `dbfilter`, or behind a reverse proxy.
Protocol: Salvor Connector protocol v1 (`docs/CONNECTOR-PROTOCOL.md` in the Salvor connector repo).

Branches: `19.0`, `18.0`, `17.0` (and `16.0`, see its README note).

## Install
1. Add this repository to `addons_path`, update the apps list, install **Salvor Connector**.
2. Developer mode → Settings → Technical → Salvor Connector.
3. Paste the pairing code from Salvor (Add database → Connector) and click **Connect**.

## Endpoints (`POST /salvor/v1/<name>`)
| Endpoint | Body | Result |
|---|---|---|
| `info` | – | JSON: protocol, versions, db size, filestore estimate, drill flag |
| `backup` | `{"format": "dump"\|"zip"}` | streamed `application/octet-stream`, header `X-Salvor-Format` |
| `restore` | multipart `file` + `name` | only when drills are enabled; new `salvor_drill_*` db only |
| `drop` | `{"name"}` | drops a `salvor_drill_*` db only |

Required headers: `Authorization: Bearer <token>`, `X-Salvor-Db: <db>`.
Odoo must route the request to a database before the module code runs: send `X-Odoo-Database: <db>`
too (Odoo 19+), or ensure the URL resolves to the database (single db, per-host `dbfilter`, or a
session cookie obtained from `/web/login?db=<db>`).

Errors: `{"error", "message"}` with 401 (token / not paired), 403 (IP, disabled, drills off),
404 (db), 409 (busy), 422 (bad arguments).

## Security
- Only `sha256(token)` is stored; compared with `hmac.compare_digest`. Tokens never logged.
- Source IP allowlist (IP or CIDR); empty list refuses everything. `X-Forwarded-For` is used
  (right-most entry) only when Odoo runs with `proxy_mode`.
- One backup/restore at a time per database (`flock` in `data_dir`, works across prefork workers).
- Drills are off by default; restore/drop accept only `^salvor_drill_[a-z0-9_]{1,40}$` and never
  the live database.
- Every call is audited in `ir.logging` (Settings → Technical → Logging).
- The only outbound call is the HTTPS pairing POST (TLS verified, 30 s timeout).

## Operational notes
- In prefork mode Odoo's `limit_time_real` also applies to a streamed backup; raise it (or serve
  `/salvor/` from a threaded/gevent worker) for large databases.
- Reverse proxies should not buffer `/salvor/v1/backup` (`proxy_buffering off` in nginx; the
  response carries `X-Accel-Buffering: no`) and need generous read timeouts.

## Tests
```
odoo-bin -d <throwaway> --addons-path=<odoo>/addons,<this repo> -i salvor_connector \
  --test-enable --stop-after-init --http-port=<free port>
```
