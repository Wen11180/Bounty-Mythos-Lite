# Residual checklist — my-gh-vikunja (optional)

Static package trial expected **refute** (guards present).

| ID | Question | Static status |
| --- | --- | --- |
| VK-R1 | Task read gated by Project.CanRead after load? | **held** |
| VK-R2 | Task update/delete use canDoTask -> Project.CanWrite? | **held** |
| VK-R3 | Cross-project move requires write on target? | **held** (modeled) |
| VK-R4 | Share-auth project-id scoped? | **held** (documented; not primary model path) |
| VK-R5 | Bulk task / attachments siblings? | **not checked this package** |

Live residual: researcher-owned loopback only.