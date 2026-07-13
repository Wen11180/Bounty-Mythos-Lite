# Residual checklist — my-gh-mealie-mass (optional)

Static package trial expected **refute** (assert_user_change_allowed present before update_user).

| ID | Question | Static status |
| --- | --- | --- |
| ML-MASS-R1 | Self-update calls assert_user_change_allowed before persist? | **held** (crud.py) |
| ML-MASS-R2 | permission_attrs block self privilege escalation? | **held** (_helpers.py) |
| ML-MASS-R3 | Non-admin cannot edit other users? | **held** |
| ML-MASS-R4 | Non-admin cannot change group/household? | **held** |
| ML-MASS-R5 | Admin self cannot change own permission_attrs? | **held** |
| ML-MASS-R6 | Admin API update_one uses UserOut residual vs self-demote check? | **held_documented** (separate admin route; self-demote 403) |

Live residual: researcher-owned loopback only; no real account takeover.