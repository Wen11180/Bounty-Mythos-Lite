# Mythos Closed Loop Quality Gate Design

## Goal

Make Bounty Mythos-Lite prove one complete, safe research loop from authorized input to reusable learning memory.

The loop is:

```text
artifact -> pipeline run -> validation workspace -> manual observation
-> claim review -> finding candidate -> learning outcome -> brain profile
```

This is not a live validation engine. It is a quality gate that proves the existing research workflow can preserve safety, evidence, review state, provenance, and learning signal continuity.

## Scope

Implement the smallest backend and frontend changes needed to make one closed-loop run inspectable.

In scope:

- A backend regression test that drives the complete loop through public API endpoints.
- Minimal API or payload additions if the current response shape cannot expose the loop state clearly.
- A visible closed-loop status summary in the existing run, report, or validation workspace frontend surfaces.
- Documentation updates only where they clarify the new closed-loop acceptance criteria.

Out of scope:

- Automatic requests to public targets.
- Browser automation against third-party systems.
- Automatic validation execution.
- Automatic platform submission.
- Full authentication, tenancy, or permission model.
- Complex knowledge graph, vector search, or long-term storage redesign.

## Success Criteria

1. A test can create or reuse a dry-run pipeline run, record a safe manual observation, approve a claim with sanitized evidence, promote a finding candidate, submit a learning outcome, and observe an updated brain profile.
2. The finding candidate remains a candidate. Its validation status must stay `validation_plan_ready`; it must not become accepted, report-ready, human-submitted, or safely validated.
3. Unsafe evidence refs such as raw bearer tokens remain redacted and cannot unblock promotion.
4. The learning outcome records evidence quality and outcome metadata without copying sensitive observation text into artifact usage records.
5. Frontend readers can see whether a run has closed-loop progress without needing to infer it from raw JSON.
6. Existing verification remains green: backend pytest, frontend lint, and frontend build.

## Current Architecture

The codebase already has most loop pieces:

- FastAPI endpoints in `apps/api/app/main.py`.
- Pipeline payload and run records persisted through `PipelineRunRecord`.
- Report preview and claim ledger logic in `apps/api/app/mythos_report/__init__.py`.
- Finding candidate promotion logic in `apps/api/app/mythos_finding/__init__.py`.
- Learning signal and brain profile logic in `apps/api/app/mythos_brain/__init__.py`.
- Frontend API types and fetch helpers in `apps/web/lib/api.ts`.
- Run/report/workspace pages under `apps/web/app/runs`, `apps/web/app/reports`, and `apps/web/app/validation-workspace`.

The first implementation should reuse these surfaces rather than introduce a new subsystem.

## Proposed Approach

Add a closed-loop summary derived from existing persisted payloads and records.

The backend should compute a small summary for a run:

```json
{
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
    "candidate_not_validated"
  ]
}
```

Status values should be simple and ordered:

- `not_started`
- `manual_observation_recorded`
- `claim_reviewed`
- `finding_candidate_created`
- `candidate_learning_recorded`
- `blocked`

The summary can live inside the existing pipeline run detail payload. If a frontend page needs report preview access, reuse existing `getPipelineRun` and avoid adding a new fetch path.

## Data Flow

1. `POST /mythos/pipeline/dry-run` creates a safe run and artifact.
2. `POST /mythos/pipeline/runs/{run_id}/manual-observations` records sanitized evidence refs for a specific claim.
3. `POST /mythos/pipeline/runs/{run_id}/claim-review-decisions` records human review for that claim.
4. `POST /mythos/pipeline/runs/{run_id}/finding-candidates` creates a candidate from eligible reviewed observed claims.
5. `POST /mythos/brain/outcomes` records an outcome linked to the run.
6. `GET /mythos/pipeline/runs/{run_id}` exposes the closed-loop summary.
7. `GET /mythos/brain/programs/{program_id}` reflects the learning signal in the program profile.

## Error Handling

The loop must fail closed:

- Unknown run id returns 404.
- Unknown claim id returns 404 or existing validation error behavior.
- Evidence refs that redact to `[REDACTED]` cannot count as safe evidence.
- A finding candidate cannot be created from unreviewed, unobserved, blocked, or unsafe claims.
- A learning outcome may be recorded only as advisory memory; it must not alter validation or submission state.

## Frontend Design

Add a compact "Closed loop" status block to the existing run detail or validation workspace page.

It should show:

- Current loop status.
- Counts for observations, reviewed claims, finding candidates, and learning signals.
- Safety notes.
- Blocked reasons when present.

Do not add a new top-level navigation item. The run detail page is the best first home because the loop belongs to a pipeline run.

## Testing

Use TDD for implementation.

Backend first:

- Add one failing API test for the full loop.
- Add one failing safety test if the current suite does not already cover the specific learning-after-promotion path.
- Implement the minimum backend summary code.

Frontend second:

- Type the new summary in `apps/web/lib/api.ts`.
- Render fallback-safe UI on the run detail page.
- Verify with `npm run lint` and `npm run build`.

Full verification:

```powershell
cd apps/api
python -m pytest

cd ../web
npm run lint
npm run build
```

## Tradeoffs

This approach does not make the system more autonomous. That is intentional. The highest priority is proving that human-controlled research state moves through the system without losing safety, provenance, and learning context.

Adding a derived summary is less ambitious than a new workflow engine, but it fits the current codebase and gives immediate product value: users can see whether a candidate has actually completed the safe research loop.
