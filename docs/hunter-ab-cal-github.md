# Hunter A+B — Cal.com GitHub package

## Package
- Path: `authorized_packages/my-gh-cal`
- package_id: `my-gh-cal-booking-authz-lab`
- Upstream: calcom/cal.com
- Version pin: **v6.2.0** (@calcom/web)
- Expected disposition: **refute**

## Model
Booking confirm / editLocation / get via `BookingAccessService.doesUserIdHaveAccessToBooking`:
1. organizer (`booking.userId` → owner_id_filter)
2. multi-host
3. team/org admin residual (group_id_filter)

## Trial
- `docs/hunter-ab-cal-trial.json` / `.md`
- **3 decisions / 0 finals / all refuted** / decision_quality **pass**
- Evidence refs: `code:code.ts:owner_id_filter`

## Residuals
See `authorized_packages/my-gh-cal/_extract/RESIDUAL_CHECKLIST.md` (CAL-R1..R6).

## Notes
- PermissionCheckService always-true stubs in some trees are **not** treated as product authz.
- Live residual only on researcher-owned self-hosted Cal.com.
- Security contact: security@cal.com