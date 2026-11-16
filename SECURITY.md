# Security policy and advisories

Report a vulnerability privately, either way:
- **GitHub private vulnerability reporting**: on this repository, **Security → Report a vulnerability**;
- **email** to **security@salvorcloud.com**.

Please do not file public issues for security problems. For anything else (installation, pairing,
backups) write to **support@salvorcloud.com**.

Releases are signed tags `<odoo series>-<module version>` (SSH-signed, shown as *Verified* on GitHub),
from 2.0.4 on: `17.0-2.0.4` … `20.0-2.0.6`, and one per later version. Pin a tag to control what you
install. Signing key: ED25519 `SHA256:xZlGFj2cTC7LTGMxb0YDlfE1J+GC1gakO807ffiw0VE` (comment
"salvor_connector release signing", identity `security@salvorcloud.com`). To check a tag, put that key
in an allowed-signers file (`security@salvorcloud.com ssh-ed25519 AAAA...`), set
`git config gpg.ssh.allowedSignersFile <file>`, then run `git verify-tag <tag>`; compare the
fingerprint it prints with the one above. Advisories are listed under
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
1. Upgrade to the latest version (2.0.8; 2.0.4 or later fixes the issue) on every database where the module is installed: pull your branch
   (`17.0`, `18.0`, `19.0` or `20.0`), **restart Odoo** (it keeps running the old Python code until it
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
