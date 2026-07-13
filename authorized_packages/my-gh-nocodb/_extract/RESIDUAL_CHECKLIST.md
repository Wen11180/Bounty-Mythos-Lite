# Residual checklist — my-gh-nocodb (optional)

Static package trial expected **refute** (guards present).

| ID | Question | Static status |
| --- | --- | --- |
| NC-R1 | dataList gated by @Acl dataList before body? | **held** |
| NC-R2 | dataUpdate/dataDelete require EDITOR+ permissions? | **held** |
| NC-R3 | Non-member of base denied (group/base scope)? | **held** (modeled) |
| NC-R4 | GlobalGuard required before ACL evaluation? | **held** (documented) |
| NC-R5 | Bulk insert/update/delete and nested data siblings? | **not checked this package** |

Live residual: researcher-owned loopback only.