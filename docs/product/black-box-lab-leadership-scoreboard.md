# Black-box lab leadership scoreboard

**Claim scope:** synthetic dual-role HAR local-lab quality only.

**Not claimed:** XBOW live-target superiority, remote observe automation, or auto-submission.

Updated: 2026-07-15

## What "leading" means here

For authorized black-box research on dual-role traffic:

1. Higher **review-ready / submittable candidate quality per human hour** than scan-volume tools.
2. Explicit **refutation** before retain (intended sharing, weak status-only signals).
3. **Zero policy violations** in outputs: no raw secrets, no remote auto-attack, no auto report submit.
4. Multi-family coverage: all five planner families must both retain TPs and kill FPs on the lab corpus.

## Current lab corpus (golden packages)

| Package | Mode | Expected |
| --- | --- | --- |
| `retain_bola_widgets` | `bola` | cross-account retained + multi-step falsify survive |
| `retain_lower_role_widgets` | `bola` | lower-role retained |
| `retain_unauth_widgets` | `bola` | unauthenticated retained |
| `retain_multi_family_bola` | `bola` | three core families retained in Top-N |
| `retain_parent_child_bola` | `bola` | parent/child swap retained (broken binding) |
| `retain_state_transition_bola` | `bola` | reversible state transition retained |
| `refute_guarded_widgets` | `guarded` | cross-account suppressed (weak signal kill) |
| `refute_lower_role_guarded_widgets` | `guarded` | lower-role suppressed |
| `refute_unauth_guarded_widgets` | `guarded` | unauthenticated suppressed |
| `refute_shared_widgets` | `shared` | cross-account **refuted** (intended sharing) |
| `refute_parent_child_guarded` | `guarded` | parent/child suppressed (binding enforced) |
| `refute_state_transition_rollback` | `rollback_failure` | state transition suppressed (rollback stop) |

## Leadership metrics (must all be 1.0 on lab set)

| Metric | Meaning |
| --- | --- |
| `golden_pass_rate` | All golden packages pass retain/refute gate |
| `safety_rate` | No high-risk secret markers in pipeline JSON |
| `iso_pass_rate` | HAR and browser-demo intakes yield same plan classes/routes |
| `falsify_coverage` | Matching Top-N cards include falsify attempts |
| `retain_hit` | Expected retain packages retain the target trial class |
| `refute_kill` | Expected refute packages kill with falsify outcome |
| `family_retain_coverage` | All required families have a retain golden |
| `family_refute_coverage` | All required families have a refute/suppress golden |

## Required families (5)

1. `cross_account_object_swap`
2. `lower_role_replay`
3. `unauthenticated_read_only_replay`
4. `owned_parent_child_swap`
5. `reversible_out_of_order_state_transition`

## Gate commands

```powershell
cd apps/api
python -m pytest tests/test_black_box_har_golden.py tests/test_black_box_leadership_gate.py -q
python -m app black-box-leadership-gate --out tmp/bb-leadership.json
```

## Next toward real TOP1 (not lab-only)

1. Parent/child intake edge cases (deeper nesting, multi-tenant paths).
2. Authorized local-target precision (A+B code/API) with the same falsify discipline — **lab slice started**: see `ab-falsify-leadership-scoreboard.md`.
3. Human-hour quality scorecard against peer tools on authorized programs — **lab proxy started**: see human-hour-quality-scoreboard.md. Live-program calibration still required before any live superiority claim.
