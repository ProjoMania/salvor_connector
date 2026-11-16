# Release tags

Signed annotated tags, one per branch and version: `<odoo series>-<module version>`, SSH-signed and
shown as *Verified* on GitHub. **Created: 2.0.4, 2.0.5 and 2.0.6 on all four branches.** Tags for 1.0.0
to 2.0.3 below are not created (historical reference only). Create a new one with
`git tag -s <name> <commit> -m "salvor_connector <module version> for Odoo <series>"`.

The commit for each version is the last commit before the next version bump (a version bump commit
and its follow-ups share one module version). For every version except 2.0.1 that commit was the
published branch head; **2.0.1 was never a branch head on GitHub**: its commits are reachable in the history
only, so nobody installed 2.0.1 from a branch head. Times given
here are push times (UTC). 1.0.0 and 2.0.0 heads are derived from the history; confirm them against
the push log (`STATUS.md` deploy rows, GitHub "Activity") before tagging.

| Module version | 17.0 | 18.0 | 19.0 | 20.0 | Status |
|---|---|---|---|---|---|
| 1.0.0 (`NN.0.1.0.0`) | `4106b3b` → `17.0-1.0.0` | `223f31c` → `18.0-1.0.0` | `028d230` → `19.0-1.0.0` | `e85793f` → `20.0-1.0.0` | **affected** (v1 `restore` through psql when the drill switch is on) |
| 2.0.0 (`NN.0.2.0.0`) | `70029ad` → `17.0-2.0.0` | `4338e3f` → `18.0-2.0.0` | `378dd36` → `19.0-2.0.0` | `966ceb4` → `20.0-2.0.0` | **affected** (pushed ~04:20 UTC 2026-11-15; no guard) |
| 2.0.1 (`NN.0.2.0.1`) | `fbe7e59` → `17.0-2.0.1` | `3c30fcd` → `18.0-2.0.1` | `6532c48` → `19.0-2.0.1` | `0b155b0` → `20.0-2.0.1` | **affected** (guard bypassable; never a branch head, history only) |
| 2.0.2 (`NN.0.2.0.2`) | `30fb87c` → `17.0-2.0.2` | `9d99f74` → `18.0-2.0.2` | `7c4b8ba` → `19.0-2.0.2` | `cefeee7` → `20.0-2.0.2` | not exploitable (drill routes 410 first; code unreachable) |
| 2.0.3 (`NN.0.2.0.3`) | `8fbc061` → `17.0-2.0.3` | `738bc80` → `18.0-2.0.3` | `ea97e4c` → `19.0-2.0.3` | `84c0e10` → `20.0-2.0.3` | not exploitable |
| 2.0.4 (`NN.0.2.0.4`) | `dae780e` → `17.0-2.0.4` | `be2c540` → `18.0-2.0.4` | `d6090d7` → `19.0-2.0.4` | `662deda` → `20.0-2.0.4` | **fixed**: restore code removed |
| 2.0.5 (`NN.0.2.0.5`) | `4b789d4` → `17.0-2.0.5` | `7a2a988` → `18.0-2.0.5` | `e16bc02` → `19.0-2.0.5` | `dd9c753` → `20.0-2.0.5` | fixed; stubs authenticated |
| 2.0.6 (`NN.0.2.0.6`) | `ae92319` → `17.0-2.0.6` | `081c377` → `18.0-2.0.6` | `ab8dc36` → `19.0-2.0.6` | `fe901a2` → `20.0-2.0.6` | fixed; body limit on every route, reporting paths |
| 2.0.7 (`NN.0.2.0.7`) | 2.0.7 commit on `17.0` → `17.0-2.0.7` | on `18.0` → `18.0-2.0.7` | on `19.0` → `19.0-2.0.7` | on `20.0` → `20.0-2.0.7` | fixed; docs and store metadata only |

The 2.0.7 hashes are the branch heads after the 2.0.7 commit (reported with the commit; this file
cannot contain its own commit's hash).

Notes:
- Each 1.0.0 head is the parent of the 2.0.0 bump commit on that branch (`62e97a0`, `36624ad`, `b7cf5c7`,
  `1acb4b0`); `028d230` on 19.0 is the commit a reviewer cited, and matches.
- Each 2.0.0 head is the parent of the 2.0.1 bump commit (`b2fc8e9`, `e0bd0b1`, `01059f0`, `c8a3118`).
- Each 2.0.1 head is the parent of the 2.0.2 commit. On 19.0 the 2.0.1 range is `01059f0..6532c48`.
- Branch `16.0` never had the connector's drill feature and gets no tags.
