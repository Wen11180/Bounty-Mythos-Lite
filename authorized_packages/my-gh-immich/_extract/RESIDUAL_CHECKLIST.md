# Residual checklist — my-gh-immich (optional)

Static package trial expected **refute** (guards present).

| ID | Question | Static status |
| --- | --- | --- |
| IM-R1 | get() calls requireAccess AssetRead before body? | **held** |
| IM-R2 | update/delete require owner checkOwnerAccess? | **held** |
| IM-R3 | Non-owner read only via album/partner share? | **held** (modeled) |
| IM-R4 | Shared-link path separate and permission-scoped? | **held** (documented) |
| IM-R5 | Bulk update/delete and metadata siblings? | **not checked this package** |

Live residual: researcher-owned loopback only.
