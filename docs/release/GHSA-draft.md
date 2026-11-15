# GitHub Security Advisory draft (do not publish before review)

**Title:** Restore drills in salvor_connector could run psql meta-commands (OS command execution)

**Ecosystem / package:** Other / `salvor_connector` (Odoo addon, github.com/ProjoMania/salvor_connector)

## Summary
With restore drills enabled, the Salvor Connector Odoo module restored an uploaded archive by piping its
SQL into `psql`. `psql` executes backslash meta-commands in its input, so a crafted archive could run
`\!` (an OS command as the Odoo service user) or `\connect` (switch to another database the Odoo role can
reach). Version 1.0.0 did this on `/salvor/v1/restore`; 2.0.0 did it in the drill flow with no filtering;
2.0.1 added a meta-command filter that an internal review bypassed. In addition, the archive's plain SQL
ran with the rights of the role that owns the live database. 2.0.2 refuses every drill call before any
work; 2.0.4 removes the restore code.

## Severity
**High, CVSS 3.1 8.0** — `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H`
- AV:N: the routes are HTTP endpoints of the Odoo server.
- AC:H: needs a non-default configuration (an administrator ticked *Allow restore drills*) and a request
  from an address on the allow list (Salvor's egress IP, set at pairing).
- PR:H: needs the connector token Salvor issued at pairing (stored only as a hash in Odoo); in practice a
  leaked token or a compromised Salvor.
- UI:N: no user interaction.
- S:C: the impact leaves the module's authority: OS commands as the Odoo service user, other databases.
- C/I/A:H: full read/write of the Odoo host account and databases reachable by the Odoo role.
Medium would apply if only one precondition were weighed; the scope change and full impact make High
the honest rating.

## Affected versions
| Branch | Affected | Patched (not exploitable) | Code removed |
|---|---|---|---|
| 17.0 | >= 17.0.1.0.0, < 17.0.2.0.2 | 17.0.2.0.2 | 17.0.2.0.4 |
| 18.0 | >= 18.0.1.0.0, < 18.0.2.0.2 | 18.0.2.0.2 | 18.0.2.0.4 |
| 19.0 | >= 19.0.1.0.0, < 19.0.2.0.2 | 19.0.2.0.2 | 19.0.2.0.4 |
| 20.0 | >= 20.0.1.0.0, < 20.0.2.0.2 | 20.0.2.0.2 | 20.0.2.0.4 |

Module versions: affected >= 1.0.0, < 2.0.2. Patched: 2.0.2 (drill routes answer 410 before any work;
the restore code is unreachable). Fixed: 2.0.4 (restore code removed). Exact commits: `docs/release/TAGS.md`.

## Weaknesses
- CWE-78: Improper Neutralization of Special Elements used in an OS Command (`\!` via psql)
- CWE-94: Improper Control of Generation of Code ('Code Injection') (archive SQL/meta-commands executed)

## Workarounds
- Keep *Allow restore drills* unticked (the default) until upgraded: Settings → Salvor Connector →
  Settings (2.x), Settings → Technical → Salvor Connector (1.x).
- Restrict `/salvor/` to Salvor's address at nginx or the firewall.
- If a token may have leaked: *Disconnect* in Odoo and pair again.
- Salvor (the service) refuses to pair or back up through connectors below 2.0.2.

## Patches
Upgrade to the latest version (2.0.6; 2.0.4 or later fixes the issue): pull the branch (signed tags
`<series>-<version>`: tag to be created), restart Odoo, upgrade the module.

## Credits
Found in internal review (ProjoMania).
