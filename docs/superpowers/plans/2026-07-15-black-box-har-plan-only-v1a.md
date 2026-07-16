# V1a Black-Box HAR Plan-Only Pipeline

Date: 2026-07-15

## Goal

Deliver the cheapest black-box L2 bootstrap:

```text
role-tagged HAR pair (A/B)
  -> redacted research events
  -> ObservedWorkflowModel
  -> supported DifferentialPlan list (partial OK)
  -> plan-only candidate projection
```

No live requests. No browser. No raw secrets persisted. No report submission.

References:

- `docs/superpowers/specs/2026-07-15-black-box-dual-intake-dataflow.md`
- `docs/superpowers/specs/2026-07-14-workflow-seeded-black-box-differential-hunter-design.md`
- existing `apps/api/app/black_box_hunter/`

## Defaults Locked

1. Two role HARs (`har_a` / `har_b`) or equivalent role map.
2. Research exports use aliases only (never raw auth material).
3. Local lab may observe later under `local_lab`; this V1a slice stays **plan-only**.
4. A+B Falsification Card remains deferred.

## Files

| File | Change |
| --- | --- |
| `apps/api/app/black_box_hunter/har_intake.py` | NEW: redact + build model + plan-only pipeline |
| `apps/api/app/black_box_hunter/__init__.py` | Soften planner for partial families; re-export HAR helpers |
| `apps/api/tests/test_black_box_har_intake.py` | NEW: redaction, model build, partial plans, safety |
| `docs/superpowers/plans/2026-07-15-black-box-har-plan-only-v1a.md` | This plan |

## Implementation Steps

1. RED: secret headers/cookies never appear in model/candidate projection.
2. RED: two HARs with `/widgets/{id}` GET produce cross-account plan-only candidate.
3. RED: missing parent/child does not hard-fail; emits supported read-only plans only.
4. GREEN: `har_intake.py` + planner `require_all_classes=False`.
5. Verify pytest for new tests + existing black_box planner tests.

## Acceptance

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m pytest tests/test_black_box_har_intake.py tests/test_black_box_local_lab.py -q
```

Success:

- True-positive-shaped IDOR plan appears for cross-account object swap.
- Cookie/Authorization values never appear in outputs.
- `execution_allowed` / `validation_allowed` / `report_submission_allowed` are false.
- Existing full five-class planner tests still pass with default `require_all_classes=True`.

## Out of Scope

- Browser demo / Playwright
- Remote lease execution
- Studio UI
- Real bounty targets
- Durable DB migration

## V1a.1 Local-Lab Observe (completed 2026-07-15)

```text
HAR pair -> plans -> LocalLabTransport stages -> evaluate_differential_evidence
  -> retained | refuted | suppressed | needs_evidence
```

Files:

- `apps/api/app/black_box_hunter/local_lab_pipeline.py`
- `apps/api/tests/test_black_box_local_lab_pipeline.py`

Acceptance:

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_black_box_har_intake.py `
  tests/test_black_box_local_lab_pipeline.py `
  tests/test_black_box_local_lab.py -q
```

Proven:

- `bola` -> `review_ready` -> `retained` for cross-account swap
- `guarded` -> `suppressed` (secure denial, no strong signal)
- `shared` -> `refuted` (intended sharing)
- `local_lab=True` required; permission flags remain false; secrets redacted

## V1b Browser Demo Dual-Session Intake (completed 2026-07-15)

```text
session_a + session_b demo packages
  -> EphemeralSessionBroker (secrets in-memory only)
  -> redacted demo events / HAR projection
  -> ObservedWorkflowModel (same as HAR)
  -> plan-only OR local-lab observe
```

Files:

- `apps/api/app/black_box_hunter/browser_demo_intake.py`
- `apps/api/tests/test_black_box_browser_demo_intake.py`
- CLI: `python -m app black-box-demo --demo-a a.json --demo-b b.json --out out.json`

Demo package shape:

```json
{
  "account_alias": "account_a",
  "role_alias": "member",
  "role_rank": 10,
  "auth_headers": {"Cookie": "..."},
  "events": [{"method": "GET", "url": "http://127.0.0.1/widgets/101", "status": 200}]
}
```

Rules:

- Auth material may enter the ephemeral handle only; never events, HAR projection, model, or exports.
- Event payloads reject `headers` / bodies / cookies keys.
- Login URLs are not recordable.
- Query/fragment stripped at record time.
- No Playwright and no remote observe in this slice.

Acceptance:

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_black_box_browser_demo_intake.py `
  tests/test_black_box_har_intake.py `
  tests/test_black_box_local_lab_pipeline.py `
  tests/test_black_box_lab_cli.py -q
```

Proven:

- pickle of session/broker fails closed
- `bola` retain / `guarded` suppress / `shared` refute via browser-demo path
- CLI `--plan-only` and local-lab observe
- SECRET tokens never appear in outputs

## Remote Fail-Closed Gate (dual-intake bridge, 2026-07-15)

`remote_profile.py` + Studio remote API already enforce human-lease fail-closed
authorization (no real target required for unit/API tests).

This slice adds the **intake-facing gate**:

```text
HAR | Browser Demo
  -> plan-only candidates (always)
  -> assess_remote_observe_gate
       profile off | no runtime | lease expired/stopped | <2 sessions
         -> mode=plan_only, observe_allowed=false, http=0
       else
         -> mode=lease_bound_observe_eligible (still no auto HTTP)
  -> optional authorize dry-run (RemoteLeaseRuntime.authorize, no HTTP)
```

Files:

- `apps/api/app/black_box_hunter/remote_observe_gate.py`
- `apps/api/tests/test_black_box_remote_observe_gate.py`
- CLI: `python -m app black-box-remote-gate --har-a a.har --har-b b.har --out gate.json`
  (or `--demo-a` / `--demo-b`)

CLI always runs with profile disabled (offline fail-closed smoke). Eligible /
authorize dry-run paths are unit-tested in-process with synthetic leases.

Acceptance:

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_black_box_remote_observe_gate.py `
  tests/test_black_box_remote_profile.py `
  tests/test_black_box_remote_api.py -q
```
