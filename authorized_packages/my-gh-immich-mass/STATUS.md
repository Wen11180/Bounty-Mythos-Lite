# my-gh-immich-mass status

## Acquisition push result
- Source: public GitHub immich-app/immich (no H1 API required)
- Version pin: **v2.7.5** + static excerpts (UserUpdateMeDto + updateMe)
- Faithful mass-assignment model: field_allowlist / forbid_privilege_fields before update_user
- Trial: **1/0 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:forbid_privilege_fields
- Residual IM-MASS-R1..R5: static held / admin DTO residual documented

## Product read
Second **non-authz (mass assignment)** GitHub package (diversity beyond mealie-mass):
- Exercises user-field update sinks (update_user) and mass_assignment_check
- Hunter root_cause: missing_mass_assignment_guard
- Complements authz package my-gh-immich
- Not a bounty auto-submit package

Updated: 2026-07-12T20:42:18Z
