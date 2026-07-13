# Residual checklist - my-gh-plane-mass (optional)

Static package trial expected **refute** (UserSerializer allowlist + privilege read_only before update_user).

| ID | Question | Static status |
| --- | --- | --- |
| PLANE-MASS-R1 | Privilege fields (is_superuser/is_staff) read_only on self-update? | **held** (UserSerializer.read_only_fields) |
| PLANE-MASS-R2 | Token / email / is_bot / is_active not client-writable? | **held** (read_only_fields) |
| PLANE-MASS-R3 | partial_update only targets request.user? | **held** (get_object -> request.user) |
| PLANE-MASS-R4 | Admin-only user admin endpoints separate residual? | **held_documented** (instance admin path separate from UserSerializer self-update) |
| PLANE-MASS-R5 | ProfileSerializer nested residual? | **held_documented** (profile update path separate; primary model is UserSerializer) |

Live residual: researcher-owned loopback only.
