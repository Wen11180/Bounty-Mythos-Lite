# Immich user self-update mass package (mass-assignment family)

Updated: 2026-07-12T20:42:18Z

Package: `authorized_packages/my-gh-immich-mass`
Package id: `my-gh-immich-user-mass-lab`
Upstream: immich-app/immich **v2.7.5**
Risk family: **mass_assignment**
Expected disposition: **refute**
Trial: **1/0 refuted** (`docs/hunter-ab-immich-mass-trial.{json,md}`)

## What this proves
- Second mass-assignment GitHub package (diversity beyond mealie-mass).
- Engine maps user-update sinks (`update_user`) to `missing_mass_assignment_guard`.
- Controls `field_allowlist` / `forbid_privilege_fields` refute via `mass_assignment_check`.
- Complements authz package `my-gh-immich` without adding pure authz spam.

## Faithful upstream model
- `UserUpdateMeDto`: email/password/name/avatarColor only (no isAdmin)
- `UserAdminCreateDto` / `UserAdminUpdateDto`: isAdmin / quota / storageLabel (admin-only)
- `updateMe`: builds Updateable from allowlisted dto fields for auth user id only
- Controller: `updateMyUser` -> `updateMe`

## Residual
See `_extract/RESIDUAL_CHECKLIST.md` IM-MASS-R1..R5.

## Do not
- Attack third-party Immich hosts
- Treat refute package as confirmed vuln
- Store secrets / real user data
