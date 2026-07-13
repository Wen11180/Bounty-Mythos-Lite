# my-gh-mealie-mass status

## Acquisition push result
- Source: public GitHub mealie-recipes/mealie (no H1 API required)
- Version pin: **v3.20.1** + static excerpts (user crud + assert_user_change_allowed)
- Faithful mass-assignment model: assert_user_change_allowed before update_user
- Trial: **2/0 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:assert_user_change_allowed
- Residual ML-MASS-R1..R6: static held / admin-route residual documented

## Product read
Third **non-authz (mass assignment)** GitHub package:
- Exercises user-field update sinks (`update_user`) and `mass_assignment_check`
- Hunter root_cause: `missing_mass_assignment_guard`
- Complements recipe authz package `my-gh-mealie`
- Not a bounty auto-submit package

Updated: 2026-07-12T17:25:00Z