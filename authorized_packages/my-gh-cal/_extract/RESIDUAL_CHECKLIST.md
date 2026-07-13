# Residual checklist — my-gh-cal (optional)

Static package trial expected **refute** (guards present).

| ID | Question | Static status |
| --- | --- | --- |
| CAL-R1 | confirm gated by doesUserIdHaveAccessToBooking? | **held** (modeled) |
| CAL-R2 | organizer short-circuit (booking.userId) holds? | **held** (owner_id_filter) |
| CAL-R3 | non-organizer non-host non-admin denied? | **held** (deny) |
| CAL-R4 | team admin residual only when group_id matches? | **held** (group_id_filter) |
| CAL-R5 | EventType findById owner/users/team membership filter? | **held** (documented residual) |
| CAL-R6 | PermissionCheckService stub always-true in some trees? | **held** — not treated as product authz |

Live residual: researcher-owned loopback only.