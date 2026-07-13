# Plane user mass-assignment package (mass_assignment family)

Updated: 2026-07-13T01:37:31Z

Package: authorized_packages/my-gh-plane-mass
Package id: my-gh-plane-user-mass-lab
Upstream: makeplane/plane **v1.3.1**
Risk family: **mass_assignment**
Expected disposition: **refute**
Trial: **1/0 refuted** (docs/hunter-ab-plane-mass-trial.{json,md})

## What this proves
- Third mass_assignment GitHub package (diversity beyond mealie-mass + immich-mass).
- Engine maps update_user sink to missing_mass_assignment_guard.
- Controls field_allowlist / forbid_privilege_fields refute via mass_assignment_check.
- Complements authz package my-gh-plane without pure authz spam.

## Faithful upstream model
- UserSerializer: writable display fields; read_only_fields include is_superuser / is_staff / is_bot / is_active / token / email
- UserEndpoint.partial_update: updates request.user only after serializer gate
- Privilege/system keys cannot pass self-update allowlist

## Residual
See _extract/RESIDUAL_CHECKLIST.md PLANE-MASS-R1..R5.

## Do not
- Attack third-party Plane hosts
- Treat refute package as confirmed vuln
- Store secrets / real user data
- Re-probe H1 while 401
