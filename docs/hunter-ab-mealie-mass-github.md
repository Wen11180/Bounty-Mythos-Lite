# Mealie user mass-assignment package

Updated: 2026-07-12T17:25:00Z

Package: `authorized_packages/my-gh-mealie-mass`
Package id: `my-gh-mealie-user-mass-lab`
Upstream: mealie-recipes/mealie **v3.20.1**
Risk family: **mass_assignment**
Expected disposition: **refute**
Trial: **2/0 refuted** (`docs/hunter-ab-mealie-mass-trial.{json,md}`)

## What this proves
- Third non-authz family beyond SSRF and path: privilege-field mass assignment.
- Engine maps pure user-update sinks (`update_user` / `persist_user` / `apply_user_update`) to `missing_mass_assignment_guard`.
- Control `assert_user_change_allowed` refutes via `mass_assignment_check`.
- Complements authz package `my-gh-mealie` without pure authz spam.

## Faithful upstream model
- PUT /users/{item_id} accepts UserBase (includes admin/can_*/group/household)
- assert_user_change_allowed before repos.users.update
- permission_attrs block self privilege escalation; non-admin self-only; admin self cannot change own permission_attrs

## Residual
See `_extract/RESIDUAL_CHECKLIST.md` ML-MASS-R1..R6.

## Do not
- Attack third-party Mealie hosts
- Treat refute package as confirmed vuln
- Store secrets / real user data