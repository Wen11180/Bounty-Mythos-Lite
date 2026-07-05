# Mythos Closed Loop Quality Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a derived closed-loop status summary that proves one safe research loop can move from pipeline run through manual observation, claim review, finding candidate, and learning outcome.

**Architecture:** Reuse existing FastAPI endpoints and persisted run payloads. Add a derived `closed_loop_summary` to pipeline run detail payload, then render it on the existing run detail page. Do not add a new workflow engine, background task, or live validation capability.

**Current implementation note:** The implementation now exposes a lifecycle
narrative, not only counters. `closed_loop_summary.steps` describes Manual
Observation, Claim Review, Finding Candidate, Learning Signal, and Brain Memory
with `status`, `reason`, `safety_gate`, and `next_allowed_action`. Run detail and
run list also expose `evidence_support_summary`, derived from report preview
claim ledger state, so the dashboard can surface evidence gaps and unsafe or
redacted evidence without turning that signal into validation or submission
permission.

**Tech Stack:** FastAPI, SQLAlchemy, Pydantic, pytest, Next.js 16, React 19, TypeScript.

---

## File Map

- Modify `apps/api/tests/test_mythos_pipeline_api.py`: add API regression coverage for the complete closed loop.
- Modify `apps/api/app/main.py`: derive `closed_loop_summary` from run payload, finding records, learning signals, and safety blockers.
- Modify `apps/api/app/main.py`: derive `evidence_support_summary` from report preview claim ledger state for run detail and run list.
- Modify `apps/web/lib/api.ts`: add TypeScript types for the summary and expose it through `PipelineRunPayload`.
- Modify `apps/web/lib/workbench-detail-data.ts`: add fallback closed-loop summary for mock run details.
- Modify `apps/web/app/runs/[runId]/page.tsx`: render a compact closed-loop status block.
- Modify `apps/web/lib/pipeline-runs-data.ts`: map evidence support into dashboard radar summaries.
- Modify `apps/web/lib/pipeline-runs-data.test.ts`: test dashboard radar derivation from evidence support.
- Optional docs update only if implementation changes the spec language. Avoid docs churn otherwise.

---

## Task 1: Backend Closed Loop Regression Test

**Files:**
- Modify: `apps/api/tests/test_mythos_pipeline_api.py`

- [ ] **Step 1: Add the failing test**

Append this test near the existing validation workspace and manual observation tests:

```python
def test_pipeline_run_detail_exposes_closed_loop_summary_after_candidate_learning():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Safe test-account diff confirmed the authorization boundary.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        review_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with sanitized evidence.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert review_response.status_code == 200

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")
        assert candidate_response.status_code == 200
        candidate = candidate_response.json()
        assert candidate["validation_status"] == "validation_plan_ready"
        assert candidate["submission_recommendation"] == "promote_to_finding_candidate"

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
                "notes": "Outcome recorded from the safe fixture loop.",
                "bounty_amount": 500,
                "severity_delta": "up",
            },
        )
        assert outcome_response.status_code == 200
        profile = outcome_response.json()
        assert profile["learning_summary"]["accepted_count"] == 1
        assert profile["learning_summary"]["strong_evidence_count"] == 1

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        summary = detail["payload"]["closed_loop_summary"]

        assert summary == {
            "status": "candidate_learning_recorded",
            "manual_observation_count": 1,
            "reviewed_claim_count": 1,
            "finding_candidate_count": 1,
            "learning_signal_count": 1,
            "blocked_reasons": [],
            "safety_notes": [
                "no_live_requests",
                "test_accounts_only",
                "human_review_required",
                "candidate_not_validated",
            ],
        }
        assert "Safe test-account diff" not in str(summary)
        assert "SECRET POLICY" not in str(detail)

        artifact_id = response.json()["artifact"]["artifact_id"]
        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        usage_records = artifact_response.json()["usage_records"]
        assert any(usage["usage_type"] == "finding_candidate" for usage in usage_records)
        assert any(usage["usage_type"] == "learning_signal" for usage in usage_records)
        assert "Safe test-account diff" not in str(usage_records)
    finally:
        app.dependency_overrides.clear()
```

- [ ] **Step 2: Run the single test and confirm RED**

Run:

```powershell
cd apps/api
python -m pytest tests/test_mythos_pipeline_api.py::test_pipeline_run_detail_exposes_closed_loop_summary_after_candidate_learning -q
```

Expected: FAIL with `KeyError: 'closed_loop_summary'` or equivalent missing-field assertion.

---

## Task 2: Backend Closed Loop Summary

**Files:**
- Modify: `apps/api/app/main.py`

- [ ] **Step 1: Pass the repository into run detail builders**

Update `get_mythos_pipeline_run` so it reuses one repository instance:

```python
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return _pipeline_run_detail(record, repository)
```

Update the helper signatures:

```python
def _pipeline_run_detail_payload(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> dict:
```

```python
def _pipeline_run_detail(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> MythosPipelineRunDetail:
```

Inside `_pipeline_run_detail`, call:

```python
    payload = _pipeline_run_detail_payload(record, repository)
```

- [ ] **Step 2: Add summary derivation to run detail payload**

In `_pipeline_run_detail_payload`, after validation workspace enrichment and before `return payload`, add:

```python
    payload["closed_loop_summary"] = _closed_loop_summary(record, repository)
```

- [ ] **Step 3: Add helper functions below `_claim_validation_tasks`**

Add these helpers after `_claim_validation_tasks` and before `_claim_validation_task`:

```python
def _closed_loop_summary(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> dict:
    payload = record.payload
    manual_observations = _safe_record_list(payload.get("manual_observations"))
    claim_review_decisions = _safe_record_list(payload.get("claim_review_decisions"))
    artifact_usage_records = _closed_loop_artifact_usage_records(record, repository)
    finding_candidate_count = _closed_loop_usage_count(
        artifact_usage_records,
        "finding_candidate",
        record.id,
    )
    learning_signal_count = _closed_loop_usage_count(
        artifact_usage_records,
        "learning_signal",
        record.id,
    )
    blocked_reasons = _closed_loop_blocked_reasons(record)

    status = _closed_loop_status(
        manual_observation_count=len(manual_observations),
        reviewed_claim_count=len(claim_review_decisions),
        finding_candidate_count=finding_candidate_count,
        learning_signal_count=learning_signal_count,
        blocked_reasons=blocked_reasons,
    )

    return {
        "status": status,
        "manual_observation_count": len(manual_observations),
        "reviewed_claim_count": len(claim_review_decisions),
        "finding_candidate_count": finding_candidate_count,
        "learning_signal_count": learning_signal_count,
        "blocked_reasons": blocked_reasons,
        "safety_notes": [
            "no_live_requests",
            "test_accounts_only",
            "human_review_required",
            "candidate_not_validated",
        ],
    }


def _closed_loop_status(
    *,
    manual_observation_count: int,
    reviewed_claim_count: int,
    finding_candidate_count: int,
    learning_signal_count: int,
    blocked_reasons: list[str],
) -> str:
    if blocked_reasons:
        return "blocked"
    if learning_signal_count:
        return "candidate_learning_recorded"
    if finding_candidate_count:
        return "finding_candidate_created"
    if reviewed_claim_count:
        return "claim_reviewed"
    if manual_observation_count:
        return "manual_observation_recorded"
    return "not_started"


def _closed_loop_artifact_usage_records(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> list[dict]:
    artifact = record.payload.get("artifact")
    artifact_id = artifact.get("artifact_id") if isinstance(artifact, dict) else None
    if not artifact_id:
        return []
    artifact_record = repository.get_artifact(str(artifact_id))
    if artifact_record is None:
        return []
    return _artifact_usage_records(artifact_record)


def _closed_loop_usage_count(
    usage_records: list[dict],
    usage_type: str,
    run_id: str,
) -> int:
    return sum(
        1
        for usage in usage_records
        if usage.get("usage_type") == usage_type and usage.get("run_id") == run_id
    )


def _closed_loop_blocked_reasons(record: PipelineRunRecord) -> list[str]:
    reasons: list[str] = []
    preview = None
    try:
        preview = build_report_preview_response(record)
    except ValueError:
        reasons.append("report_preview_unavailable")

    if preview is not None and best_finding_candidate_claim(preview) is None:
        reasons.append("no_promotion_eligible_claim")

    return reasons


def _safe_record_list(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
```

Current implementation extension:

- `_closed_loop_summary` should include `steps`, with one lifecycle entry for
  each closed-loop stage. The helpers must not copy manual observation text or
  reviewer rationale into the summary.
- `_evidence_support_summary` should derive advisory claim support counts from
  `build_report_preview_response(record)`.
- `_claim_evidence_support_status` should classify claim ledger entries as
  `unsafe_or_redacted_evidence`, `human_gated_supported`,
  `missing_required_evidence`, or `partially_supported`.
- `_pipeline_run_summary` should expose `evidence_support_summary` so
  `/mythos/pipeline/runs` and `/mythos/pipeline/runs/{run_id}` agree.

- [ ] **Step 3: Run the single test and confirm GREEN**

Run:

```powershell
cd apps/api
python -m pytest tests/test_mythos_pipeline_api.py::test_pipeline_run_detail_exposes_closed_loop_summary_after_candidate_learning -q
```

Expected: PASS.

- [ ] **Step 4: Run focused API tests**

Run:

```powershell
cd apps/api
python -m pytest tests/test_mythos_pipeline_api.py tests/test_mythos_brain_api.py -q
```

Expected: all selected tests pass.

---

## Task 3: Frontend Types and Fallback Data

**Files:**
- Modify: `apps/web/lib/api.ts`
- Modify: `apps/web/lib/workbench-detail-data.ts`

- [ ] **Step 1: Add frontend type definitions**

In `apps/web/lib/api.ts`, after `ValidationWorkspace`, add:

```typescript
export type ClosedLoopSummary = {
  status: string;
  manual_observation_count: number;
  reviewed_claim_count: number;
  finding_candidate_count: number;
  learning_signal_count: number;
  blocked_reasons: string[];
  safety_notes: string[];
  steps?: ClosedLoopStep[];
};

export type ClosedLoopStep = {
  key: string;
  label: string;
  status: string;
  reason: string;
  safety_gate: string;
  next_allowed_action: string;
};
```

Then add this field to `PipelineRunPayload`:

```typescript
  closed_loop_summary?: ClosedLoopSummary | null;
```

- [ ] **Step 2: Add fallback summary to run detail fallback**

In `apps/web/lib/workbench-detail-data.ts`, inside the `payload` object returned by `fallbackRunDetail`, add:

```typescript
      closed_loop_summary: {
        status: "not_started",
        manual_observation_count: 0,
        reviewed_claim_count: 0,
        finding_candidate_count: 0,
        learning_signal_count: 0,
        blocked_reasons: [],
        safety_notes: [
          "no_live_requests",
          "test_accounts_only",
          "human_review_required",
          "candidate_not_validated",
        ],
      },
```

- [ ] **Step 3: Run TypeScript build check through Next build**

Run:

```powershell
cd apps/web
npm run build
```

Expected: build passes. If the build fails, fix type errors before moving on.

---

## Task 4: Run Detail Closed Loop UI

**Files:**
- Modify: `apps/web/app/runs/[runId]/page.tsx`

- [ ] **Step 1: Read summary from payload**

Near existing payload-derived constants, add:

```typescript
  const closedLoop = payload?.closed_loop_summary;
  const closedLoopBlockedReasons = safeStringList(closedLoop?.blocked_reasons);
  const closedLoopSafetyNotes = safeStringList(closedLoop?.safety_notes);
```

- [ ] **Step 2: Add a metric for closed-loop status**

Change the metrics grid from `xl:grid-cols-5` to `xl:grid-cols-6`, and add:

```tsx
        <Metric label="Loop" value={formatLabel(closedLoop?.status ?? "not_started")} />
```

- [ ] **Step 3: Add a closed-loop aside card**

Add this card at the top of the `<aside>` before the Validation Gate section:

```tsx
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="Closed Loop" />
            <div className="grid gap-4 p-5 text-sm">
              <p className="font-semibold text-[var(--accent-strong)]">
                {formatLabel(closedLoop?.status ?? "not_started")}
              </p>
              <dl className="grid grid-cols-2 gap-3">
                <Field label="Observations" value={closedLoop?.manual_observation_count ?? 0} />
                <Field label="Reviews" value={closedLoop?.reviewed_claim_count ?? 0} />
                <Field label="Candidates" value={closedLoop?.finding_candidate_count ?? 0} />
                <Field label="Learning" value={closedLoop?.learning_signal_count ?? 0} />
              </dl>
              {/* Render closedLoop.steps here as the lifecycle narrative. */}
              {closedLoopSafetyNotes.length > 0 ? (
                <ul className="flex flex-wrap gap-1.5">
                  {closedLoopSafetyNotes.map((note) => (
                    <li
                      key={`closed-loop-note-${note}`}
                      className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                    >
                      {formatLabel(note)}
                    </li>
                  ))}
                </ul>
              ) : null}
              {closedLoopBlockedReasons.length > 0 ? (
                <div className="border-t border-[var(--line)] pt-3">
                  <p className="font-semibold">Blocked</p>
                  <ul className="mt-2 grid gap-1 text-[var(--muted)]">
                    {closedLoopBlockedReasons.map((reason) => (
                      <li key={`closed-loop-blocked-${reason}`}>{formatLabel(reason)}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          </section>
```

- [ ] **Step 4: Verify frontend**

Run:

```powershell
cd apps/web
npm test
npm run lint
npm run build
```

Expected: lint and build pass with no warnings or errors.

---

## Task 5: Full Verification and Commit

**Files:**
- All files touched in Tasks 1-4.

- [ ] **Step 1: Run backend suite**

Run:

```powershell
cd apps/api
python -m pytest
```

Expected: all tests pass.

- [ ] **Step 2: Run frontend suite**

Run:

```powershell
cd apps/web
npm run lint
npm run build
```

Expected: lint and build pass.

- [ ] **Step 3: Review git diff**

Run:

```powershell
git diff --stat
git diff --name-only
```

Expected touched files:

```text
apps/api/app/main.py
apps/api/tests/test_mythos_pipeline_api.py
apps/web/app/runs/[runId]/page.tsx
apps/web/lib/api.ts
apps/web/lib/workbench-detail-data.ts
docs/superpowers/plans/2026-07-04-mythos-closed-loop-quality-gate.md
```

- [ ] **Step 4: Commit**

Run:

```powershell
git add apps/api/app/main.py apps/api/tests/test_mythos_pipeline_api.py apps/web/app/runs/[runId]/page.tsx apps/web/lib/api.ts apps/web/lib/workbench-detail-data.ts docs/superpowers/plans/2026-07-04-mythos-closed-loop-quality-gate.md
git commit -m "feat: expose mythos closed loop summary"
```

Expected: one commit with only the planned files.

---

## Self-Review Notes

- Spec coverage: The plan adds the closed-loop API proof, derived status summary, frontend visibility, and full verification from the approved spec.
- Scope guard: The plan does not add live requests, automated validation execution, browser automation, submission, auth, tenancy, vector search, or graph storage.
- TDD: Task 1 requires a failing backend test before implementation.
- Safety: The finding candidate remains `validation_plan_ready`; learning remains advisory memory.
