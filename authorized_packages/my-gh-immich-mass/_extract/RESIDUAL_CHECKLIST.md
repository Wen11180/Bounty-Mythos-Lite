# Residual checklist — my-gh-immich-mass (optional)

Static package trial expected **refute** (field allowlist + privilege forbid present before update_user).

| ID | Question | Static status |
| --- | --- | --- |
| IM-MASS-R1 | UserUpdateMeDto excludes isAdmin / quota / storageLabel? | **held** (user.dto.ts) |
| IM-MASS-R2 | updateMe only copies allowlisted dto fields into Updateable? | **held** (user.service.ts) |
| IM-MASS-R3 | Self-update targets auth user id only (not arbitrary id)? | **held** (updateMe uses user.id) |
| IM-MASS-R4 | Empty/unsafe privilege residual fail-closed in model? | **held** (model deny) |
| IM-MASS-R5 | Admin UserAdminUpdateDto isAdmin path residual? | **held_documented** (admin-only DTO; not self-update model) |

Live residual: researcher-owned loopback only.
