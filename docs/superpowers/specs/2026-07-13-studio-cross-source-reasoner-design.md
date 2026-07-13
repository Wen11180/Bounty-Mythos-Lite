# Studio Cross-Source Reasoner Design

Date: 2026-07-13

## Context

Mythos Studio already builds a redacted cross-source fact pack and runs the
Candidate Hunter refutation, deduplication, evidence, and ranking loop. The
production Studio path currently calls `generate_cross_source_candidates()`
with no model configuration or reasoner, so it can only reuse baseline static
candidates.

This change connects the existing `RegistryCandidateReasoner` to one explicitly
authorized Studio run. It does not grant validation, execution, promotion, or
report-submission permission.

## Goals

- Keep model-assisted candidate generation disabled by default.
- Require an explicit decision for each Studio run.
- Read API keys only from backend environment variables.
- Validate every model proposal against the existing strict schema and
  `allowed_fact_refs` before it reaches Candidate Hunter.
- Fall back to baseline candidates when the provider or model output fails.
- Record enough metadata to audit the model call without persisting prompts,
  raw responses, secrets, or authorization material.
- Preserve all existing Scope Guard, human review, evidence, and
  submission-blocked invariants.

## Chosen Approach

Use request-scoped opt-in configuration. Global automatic enablement is too
implicit, and workspace-persisted enablement could unintentionally authorize a
later run. A single-run request makes the decision visible, bounded, and
auditable.

## Request Contract

`POST /mythos/studio/workspaces/runs` accepts an optional `candidate_model`
object:

```json
{
  "workspace_path": "C:/authorized/workspace",
  "candidate_model": {
    "enabled": true,
    "provider": "openai",
    "model": "configured-model-name"
  }
}
```

Rules:

- A missing `candidate_model` is equivalent to `enabled=false`.
- When disabled, `provider` and `model` must be absent.
- When enabled, `provider` and a non-empty `model` are required.
- Provider is limited to the existing `openai`, `claude`, and `deepseek`
  registry values.
- No request, response, manifest, database record, or UI field accepts an API
  key.

## Runtime Flow

1. Validate the request before creating a pipeline run.
2. Run the existing local source audit and build the redacted Fact Pack.
3. If model assistance is disabled, keep the current baseline-only path and do
   not instantiate a provider.
4. If enabled, construct `CandidateModelConfig` and
   `RegistryCandidateReasoner` using the existing backend registry.
5. Make at most one model call with the existing deterministic settings:
   `temperature=0` and `max_tokens=2400`.
6. Reject proposals that fail schema validation, cite unknown facts, contain
   sensitive content, invent a route or code path, omit a required cross-source
   link explanation, or make a forbidden confirmation/exploitation/submission
   claim.
7. Merge only accepted model proposals with baseline candidates.
8. Send the merged candidates through the existing Candidate Hunter evidence,
   refutation, deduplication, ranking, and human-review gates.
9. Return only submission-blocked research output.

## Failure Handling

- Invalid opt-in configuration returns HTTP 422 before a run is created.
- Missing API key, provider error, timeout, or invalid model output does not
  retry, switch provider, or fail the whole research run.
- Provider and model failures produce `needs_model_review` with a safe failure
  reason, then continue with baseline candidates.
- If only some proposals are valid, retain only those proposals and record
  rejection counts by safe reason.
- No path may change `execution_allowed`, `dispatch_allowed`,
  `validation_allowed`, `candidate_promotion_allowed`, or
  `report_submission_allowed` from `False`.

## Audit Record

The cross-source generation stage and existing LLM audit record store only:

- whether a model call was requested;
- provider and model name;
- model status and safe failure reason;
- prompt hash and latency;
- baseline, proposed, accepted, rejected, and working-candidate counts; and
- the forced-false safety permission fields.

They do not store the prompt, raw provider response, API key, raw source code,
cookies, tokens, authorization headers, or real user data.

## Studio UI

The Studio workbench adds a minimal, default-off model-assistance control:

- one enable checkbox;
- one provider selector; and
- one model-name input.

Provider and model controls are relevant only while enabled. The UI never
contains an API-key input and never persists the model choice to the workspace
manifest. A later run starts disabled again.

## Tests and Acceptance Criteria

Implementation follows test-driven development. The tests must prove:

1. A default Studio run neither constructs a reasoner nor calls a provider.
2. Enabled requests missing provider or model fail with HTTP 422 before run
   persistence.
3. A valid, cited model proposal reaches Candidate Hunter as an unverified
   candidate.
4. Missing keys, timeouts, provider errors, and invalid outputs keep baseline
   candidates available and report `needs_model_review`.
5. Unknown references, sensitive content, and forbidden claims are rejected.
6. Pipeline and LLM audit records contain safe metadata but no prompt, raw
   response, source content, or secret.
7. Every execution, validation, promotion, and submission permission remains
   false for successful, partial, and failed model calls.
8. The web client omits `candidate_model` by default and sends it only after an
   explicit enable action.
9. Studio exposes no API-key input.
10. Existing Candidate Hunter release benchmarks, backend safety tests, web
    tests, Studio tests, lint, and builds remain compatible.

## Explicit Non-Goals

- Persisting model enablement in a workspace.
- Automatic retry, provider fallback, or multi-model voting.
- User-configurable temperature, token limit, or system prompt.
- Connecting model output to live validation, campaign execution, finding
  promotion, or report submission.
- Adding database tables.
- Refactoring the existing `main.py` monolith in this change.
- Adding another agent, planner, bridge, or dashboard area.
