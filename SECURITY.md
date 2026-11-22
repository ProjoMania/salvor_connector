# Security policy and advisories

Report a vulnerability privately, either way:
- **GitHub private vulnerability reporting**: on this repository, **Security → Report a vulnerability**;
- **email** to **security@salvorcloud.com**.

Please do not file public issues for security problems. For anything else (installation, pairing,
backups) write to **support@salvorcloud.com**.

Releases are SSH-signed tags `<odoo series>-<module version>`, from 2.0.4 on (`17.0-2.0.4` …
`20.0-2.0.9`; from 2.0.10 also `16.0-2.0.10`), one per branch and version. Verify them with
`git verify-tag` and the key below; GitHub shows tags up to 2.0.8 as *Verified*. Pin a tag to control what you
install. Signing key: ED25519 `SHA256:xZlGFj2cTC7LTGMxb0YDlfE1J+GC1gakO807ffiw0VE`, identity
`security@salvorcloud.com`. To check a tag, save this line as an allowed-signers file:

```
security@salvorcloud.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN4g4opiVfiLrGjrDcHCIU0ISTUQUbYADBmPb9K1k1f4
```

then run `git -c gpg.ssh.allowedSignersFile=<file> verify-tag <tag>`. It prints
`Good "git" signature for security@salvorcloud.com with ED25519 key SHA256:xZlGFj2c...` . Advisories are listed under
**Security → Advisories**.

## Advisory SC-2026-01: restore drills could run psql meta-commands

GitHub advisory: [GHSA-qxmx-8p3v-m6x3](https://github.com/ProjoMania/salvor_connector/security/advisories/GHSA-qxmx-8p3v-m6x3) (published). Exact
affected commits per branch: `docs/release/TAGS.md`. Severity: High (CVSS 3.1 8.0).

| | |
|---|---|
| Component | `salvor_connector`, restore-drill feature |
| Affected | **1.0.0**: `/salvor/v1/restore` pipes the archive's SQL through `psql` when *Allow restore drills* is on. **2.0.0**: drill restore via `psql`, with no meta-command guard. **2.0.1**: a guard is in place, but it failed review (it can be bypassed). |
| Not affected | **2.0.2 and 2.0.3** (the GitHub advisory lists 2.0.2 as "patched": not exploitable from 2.0.2, while the code itself was removed in 2.0.4): every drill route raises 410 before doing any work; the restore code is still shipped but unreachable. |
| Fixed | **2.0.4**: the restore code is removed from the module. The drill routes are stubs that answer 410 `drills_removed` without reading the request body. **2.0.5**: the stubs check token, IP and enabled first, like every other route, and refuse any body over 1 KiB. |
| Preconditions | All three: a valid connector token, a request from an allowed IP address, and restore drills switched **on** (they are off by default). |
| Impact | The archive's content reaches `psql`, which runs backslash meta-commands: `\!` runs OS commands as the Odoo service user, `\c` connects to other databases the Odoo role can reach. The archive's SQL also runs with the rights of the role that owns the live database. |

### What to do
1. Upgrade to the latest version (2.0.15; 2.0.13 on `16.0`; 2.0.4 or later fixes the issue) on every database where the module is installed: pull your branch
   (`16.0`, `17.0`, `18.0`, `19.0` or `20.0`), **restart Odoo** (it keeps running the old Python code until it
   is restarted), then upgrade the module (`-u salvor_connector`, or *Upgrade* in Apps).
2. Until you have upgraded, keep **Allow restore drills** off (Settings → Salvor Connector → Settings
   on 2.x; Settings → Technical → Salvor Connector on 1.x).
3. Scratch databases named `salvor_drill_*` left by 2.0.0/2.0.1 are full copies of production. 2.0.4
   drops the ones it has on record (warning and *Drop them now* button on the settings form, the hourly
   action after 24 h, *Disconnect*, uninstall). Check your PostgreSQL server for any others (for example
   from 1.x) and drop them by hand.

Salvor (the service) refuses to pair with, back up through or otherwise call any connector below 2.0.2.
After upgrading from 1.0.0, 2.0.0 or 2.0.1, pair again: take a new pairing code in Salvor and click
**Connect** on the module's settings form.

## Advisory SC-2026-02: chunked request bodies bypassed the body-size limit

GitHub advisory: [GHSA-28rv-398c-r5xx](https://github.com/ProjoMania/salvor_connector/security/advisories/GHSA-28rv-398c-r5xx) (affected ranges and severity as published there).

| | |
|---|---|
| Component | `salvor_connector`, request handling of the `/salvor/` routes |
| Affected | Versions before **2.0.10**: a body sent with `Transfer-Encoding: chunked` (no Content-Length) was not held to the per-route limit (where one existed: 1 KiB on the drill routes from 2.0.3, 64 KiB on the working routes from 2.0.6), so Odoo read and parsed it before the token check refused the call. |
| Fixed | **2.0.10**: on every `/salvor/` route a chunked body or a declared Content-Length over the limit gets 413 before the body is parsed and before the token check (all branches, including the new 16.0). **2.0.11**: a chunked body is refused even when the request also carries a Content-Length, and the routes are no longer served on Odoo's no-database path when the module is loaded server-wide. |
| Preconditions | Network access to the Odoo server's `/salvor/` routes; no token needed. |
| Impact | Memory and CPU use on the Odoo server from large request bodies (denial of service). No data access. |

### What to do
Upgrade to the latest version (2.0.15; 2.0.13 on `16.0`; 2.0.11 or later has the complete fix): pull your branch, restart
Odoo, `-u salvor_connector`. Independently of the module, a reverse proxy that limits request bodies
(nginx `client_max_body_size`) and restricts `/salvor/` to Salvor's IP addresses also contains it.

## 2.0.12: the IP allowlist trusted `CF-Connecting-IP` by default (changed in 2.0.13)

No advisory number is assigned to this. **Do not use 2.0.12; use 2.0.13 or later.**

| | |
|---|---|
| Component | `salvor_connector`, source-IP allowlist |
| Affected | **2.0.12 only** (tags `16.0-2.0.12` to `20.0-2.0.12`). On every install, behind Cloudflare or not, a request that reached Odoo from an address in Cloudflare's published ranges had its `CF-Connecting-IP` header checked against Allowed IPs in place of the address Odoo saw. 2.0.11 and earlier never read that header. |
| Why that is weak | Cloudflare's ranges carry the traffic of every Cloudflare customer. A request from those ranges is not known to have come through the site's own zone, so its `CF-Connecting-IP` header is not known to be the caller's address. Cloudflare's [HTTP headers reference](https://developers.cloudflare.com/fundamentals/reference/http-headers/) says of one such case: "For Worker subrequests destined for a non-Cloudflare customer zone, the Worker script controls the client IP headers: both CF-Connecting-IP and x-real-ip can be altered by the Worker." |
| Preconditions | A valid access token for the database (it is checked first, on every route), and an Odoo server that accepts connections from Cloudflare's ranges. |
| Impact | The IP allowlist, a second check behind the token, could be passed from an address that is not on it. Nothing is reachable without the token. |
| Changed in | **2.0.13**: the header is read only when an administrator switches on **Odoo is behind Cloudflare** (Settings → Salvor Connector → Settings), which is off by default, and never on a request that carries a `CF-Worker` header. An upgrade from 2.0.12 leaves the switch off. |

With the switch on, the allowlist does not protect against someone who already holds the access token:
the header it relies on arrives from Cloudflare's network, which is not known to be your own zone. The
README says what stops that (Security: zone-level or per-hostname Authenticated Origin Pulls with your
own certificate). 2.0.12 also showed a false error after a successful pairing
(`docs/release/2.0.13.md`).
