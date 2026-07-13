# Residual checklist — my-gh-hedgedoc (optional)

Static package trial expected **refute** (guards present).

| ID | Question | Static status |
| --- | --- | --- |
| HD-R1 | findNote calls checkViewPermission before body? | **held** |
| HD-R2 | private note view/edit requires owner_id? | **held** |
| HD-R3 | locked/protected write owner-only in realtime? | **held** (modeled) |
| HD-R4 | limited/editable require login for write? | **held** (documented) |
| HD-R5 | permission change socket handler owner-gated? | **not checked this package** |

Live residual: researcher-owned loopback only.