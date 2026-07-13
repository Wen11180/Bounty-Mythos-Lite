# Studio Cross-Source Reasoner Implementation Plan

> **Execution rule:** Every production behavior starts with a focused failing
> test. Model assistance stays request-scoped, default-off, baseline-preserving,
> and unable to grant execution, validation, promotion, or submission permission.

## Scope

Implement the approved design in
`docs/superpowers/specs/2026-07-13-studio-cross-source-reasoner-design.md`.
Connect the existing `RegistryCandidateReasoner` to an explicitly opted-in
Studio run, persist safe audit metadata, and add the smallest usable Studio
controls.

Preserve the current uncommitted Cross-Source and Candidate Hunter work. Edit
only the files named in this plan and do not refactor adjacent code.

## Phase 0: Verified Documentation and API Boundaries

### Allowed APIs and copy-ready patterns

| Need | Existing source | Required use |
| --- | --- | --- |
| Strict model configuration | `apps/api/app/cross_source_candidate_generator.py:40` `CandidateModelConfig` | Reuse the existing provider enum, model bounds, and live-only mode. |
| Registry-backed reasoner | `apps/api/app/cross_source_candidate_generator.py:177` `RegistryCandidateReasoner` | Reuse its single deterministic call with `temperature=0` and `max_tokens=2400`. |
| Baseline-preserving generation | `apps/api/app/cross_source_candidate_generator.py:261` `generate_cross_source_candidates(...)` | Pass a config/reasoner only for an explicit opt-in; keep the current fallback result. |
| Safe generation stage | `apps/api/app/cross_source_candidate_generator.py:388` `generation_stage_payload(...)` | Extend this existing redacted payload rather than adding a second audit format. |
| Provider construction | `apps/api/app/llm/registry.py:73` `build_default_registry()` | Construct the registry only after opt-in validation. Keys remain backend settings. |
| LLM audit persistence | `apps/api/app/repository.py:172` `DatabaseRepository.save_llm_run(...)` | Store provider/model/purpose/hash/mode/latency/error/safety notes only. |
| Audit safety notes | `apps/api/app/main.py:12567` `_llm_audit_safety_notes(...)` | Copy the prompt-hash-only and provider-response-not-fact semantics. |
| Studio request model | `apps/api/app/main.py:241` `StudioWorkspaceRunRequest` | Add one nested request-scoped model configuration. |
| Studio research integration | `apps/api/app/main.py:2620` `run_mythos_studio_workspace_research(...)` | Resolve model runtime after Fact Pack creation and before generation. |
| Generator unit patterns | `apps/api/tests/test_cross_source_candidate_generator.py:146` through `:338` | Extend the real Replay/failure/baseline/stage tests. |
| Controlled Studio run | `apps/api/tests/test_studio_api.py:2824` | Extend the existing authorized workspace run and repository assertions. |
| Web request contract | `apps/web/lib/api.ts:546` and `:1271` | Extend existing request/response types and POST helper only. |
| Web request-body test | `apps/web/lib/api.test.ts:746` | Copy the intercepted-fetch body assertion pattern. |
| Studio run handlers | `apps/web/app/studio/studio-workbench.tsx:265` and `:355` | Feed the same one-run opt-in into both existing local run entrypoints. |
| Studio source-level UI tests | `apps/web/lib/studio-data.test.ts:2591` and `:2628` | Extend existing workbench contract checks without introducing a UI test framework. |

### Allowed contract additions

Backend request:

```python
class StudioCandidateModelRequest(BaseModel):
    enabled: bool = False
    provider: ProviderName | None = None
    model: str | None = Field(default=None, max_length=255)

class StudioWorkspaceRunRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    candidate_model: StudioCandidateModelRequest | None = None
```

The nested model uses an after-validator:

- enabled requires provider plus a non-blank model;
- disabled rejects provider or model; and
- an absent object stays equivalent to disabled.

Generation audit additions:

```text
model_requested
provider
model
model_status
model_failure_reason
prompt_hash
model_latency_ms
baseline_count
proposed_count
accepted_count
rejected_count
working_candidate_count
```

### Anti-pattern guards

- Do not accept, display, persist, or return an API key.
- Do not instantiate a registry when the request is disabled or absent.
- Do not add retry, provider fallback, model voting, prompt controls, or a new
  database record type.
- Do not persist the opt-in in the workspace manifest.
- Do not store prompts, raw model output, raw code, headers, cookies, tokens,
  or authorization material in Pipeline or LLM audit records.
- Do not bypass the existing proposal validator or feed raw model text to
  Candidate Hunter.
- Do not weaken any forced-false permission field.

## Phase 1: Extend Pure Generation Audit Metadata

### Files

- Update `apps/api/tests/test_cross_source_candidate_generator.py`.
- Update `apps/api/app/cross_source_candidate_generator.py`.

### RED tests

1. Extend the timeout/provider-error test to require safe latency propagation
   when the reasoner observed a provider response.
2. Extend the valid proposal test to require latency on the generation result.
3. Extend `test_generation_stage_payload_is_redacted_and_idempotent` to pass an
   optional `CandidateModelConfig` and require the approved request/status/count
   fields.
4. Add a default-off stage test proving provider/model are absent, requested is
   false, counts are correct, and all permission flags remain false.
5. Assert serialized results never contain the prompt, response text, API-key
   field names, or source content.

Run the focused test after each addition and confirm it fails for the missing
field or behavior, not for setup or syntax errors.

### GREEN implementation

1. Add optional `latency_ms` to `CandidateModelResult` and
   `model_latency_ms` to `CrossSourceGenerationResult`.
2. Preserve latency from `LLMResponse` for success and response-level errors.
   Timeout/exception paths without a response keep latency unset.
3. Thread latency through `_generation_result(...)` without changing baseline
   merge, validation, or failure semantics.
4. Extend `generation_stage_payload(...)` with optional `model_config`; derive
   safe provider/model/requested metadata and counts from existing objects.
5. Keep the existing idempotency key, redacted Fact Pack manifest, and
   hard-coded false permissions.

### Verification

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest tests/test_cross_source_candidate_generator.py -q
```

### Guards

- Do not expose the raw `LLMResponse` outside the reasoner.
- Do not alter proposal acceptance rules or Candidate Hunter ranking.
- Do not change release evaluator thresholds or fixtures.

## Phase 2: Add Request Validation and Wire the Backend Main Path

### Files

- Update `apps/api/tests/test_studio_api.py`.
- Update `apps/api/app/main.py` narrowly around request models, imports, the
  Studio run endpoint, and one small audit helper if needed.

### RED tests

1. Parameterize enabled requests missing provider or model and disabled
   requests carrying either value. Require HTTP 422 and prove no pipeline run
   or LLM audit record was created.
2. Extend the default Studio run test with a registry factory that raises if
   called. Require `model_not_requested`, no LLM audit row, baseline candidates,
   and the current submission-blocked output.
3. Add an enabled-run test using the real registry/reasoner path with a local
   fake provider. Build its JSON proposal from the request Fact Pack so it cites
   observed refs and routes. Require the accepted proposal to enter the existing
   Candidate Hunter input path as unverified evidence-bound data.
4. Add provider-error and timeout tests. Require `needs_model_review`, safe
   failure reason, one LLM audit row, and baseline candidates still available.
5. Add invalid/sensitive proposal coverage at the endpoint boundary and require
   rejection counts without raw response persistence.
6. Serialize Pipeline stages, LLM rows, response, and workspace manifest; assert
   absence of prompt text, response text, source bodies, API keys, tokens,
   cookies, and authorization headers.
7. Assert every execution, dispatch, validation, promotion, and submission
   permission remains false for default, successful, partial, and failed calls.

### GREEN implementation

1. Add the nested validated request model using the existing `ProviderName` and
   Pydantic after-validator pattern.
2. After Fact Pack creation, resolve `CandidateModelConfig` only for enabled
   requests. Build `RegistryCandidateReasoner(build_default_registry())` only in
   that branch.
3. Pass the runtime into `generate_cross_source_candidates(...)` and the config
   into `generation_stage_payload(...)`.
4. For requested calls, persist one `save_llm_run(...)` row with purpose
   `cross_source_candidate_generation`, mode `live`, safe failure reason,
   prompt hash, latency, and prompt-hash-only safety notes.
5. Expand `candidate_generation` in the response with only the approved safe
   metadata and counts.
6. Keep provider/model failure non-fatal and preserve baseline working
   candidates.

### Verification

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest tests/test_studio_api.py -q
..\..\.venv\Scripts\python.exe -m pytest tests/test_cross_source_candidate_generator.py tests/test_candidate_hunter_loop.py -q
```

### Guards

- Validation must happen before workspace loading or persistence.
- Do not call `/internal/llm/generate` from the server itself.
- Do not put provider construction in global settings startup.
- Do not turn provider errors into HTTP 5xx for the Studio research run.

## Phase 3: Add the Minimal Studio Request Controls

### Files

- Update `apps/web/lib/api.test.ts`.
- Update `apps/web/lib/studio-data.test.ts`.
- Update `apps/web/lib/api.ts`.
- Update `apps/web/app/studio/studio-workbench.tsx`.

### RED tests

1. Extend the intercepted Studio run request test: default runs must send only
   `workspace_path`.
2. Add an enabled request test requiring exactly `enabled`, `provider`, and
   `model` under `candidate_model`; assert no secret/key/token fields.
3. Extend the workbench source contract to require a default-false model toggle,
   the three allowed provider values, a model-name field, conditional controls,
   and both run handlers using one request builder.
4. Require the request builder to omit `candidate_model` while disabled and to
   block an enabled run with a blank model before POST.
5. Require the one-run authorization to reset after the request completes so a
   later run starts disabled.
6. Assert the workbench contains no API-key input and no model configuration is
   passed to workspace create/import APIs.

### GREEN implementation

1. Extend `StudioWorkspaceRunRequest` and response types with the approved
   nested config and safe audit summary.
2. Add local state for enabled/provider/model. Default to disabled and keep the
   existing provider names as the only options.
3. Add one small closure/helper that returns the run request shared by
   `handleRunLocalCandidateHunt` and `handleStartResearch`.
4. Render one checkbox and, only while enabled, the provider selector and model
   input near the existing local research controls. Never render a key input.
5. Prevent enabled runs with a blank model and report the existing blocked-log
   style message.
6. Clear the one-run opt-in in the request completion path without writing it
   to the manifest.

### Verification

```powershell
Set-Location apps/web
npm test
npm run lint
npm run build
```

### Guards

- Do not add a settings page, persistence store, new navigation area, or API-key
  control.
- Do not display raw provider errors; use the existing safe status/failure
  summary.
- Do not add an execution, approval, validation, or submission action.

## Phase 4: Focused Integration and Safety Regression

1. Run the generator, Studio API, Candidate Hunter, release runner, release
   evaluator, LLM registry, repository, and web tests together.
2. Run both 12-case release benchmark suites and require the existing metrics
   and safety failures to remain unchanged for default-off runs.
3. Search changed code for API-key request fields, prompt/raw-response
   persistence, retry loops, provider fallback, and permission assignments.
4. Confirm the default frontend request is byte-for-byte equivalent to the
   pre-feature body.

### Verification

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_cross_source_candidate_generator.py `
  tests/test_studio_api.py `
  tests/test_candidate_hunter_loop.py `
  tests/test_candidate_hunter_release_runner.py `
  tests/test_candidate_hunter_release_benchmark.py `
  tests/test_api.py `
  tests/test_database_repository.py -q

Set-Location ../web
npm test
npm run lint
npm run build

Set-Location ../studio
npm test
```

### Guards

- A perfect synthetic benchmark is compatibility evidence only; do not claim
  real-world discovery quality from this phase.
- Do not edit fixture gold or weaken a test to preserve metrics.

## Phase 5: Repository Verification and Handoff

1. Run the complete backend suite and record the exact pass/fail count.
2. Run Web tests/lint/build, Studio tests, Compose validation, and E2E.
3. Run `git diff --check` and inspect only the files changed by this plan.
4. Compare full-suite failures with the known pre-implementation baseline:
   five backend failures and the current Playwright standalone/fixed-port
   failure. This phase must introduce no additional failure. Do not describe the
   repository as green until the later engineering-baseline priority fixes them.
5. Confirm no authorized package, temporary output, raw prompt, raw model
   response, or secret was added to the commit.

### Final commands

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest -q

Set-Location ../web
npm test
npm run lint
npm run build
npm run e2e

Set-Location ../studio
npm test

Set-Location ../..
docker compose -f infra/docker-compose.yml config --quiet
git diff --check
git status --short
```

## Completion Evidence

This P0 slice is complete only when:

- default Studio runs do not construct or call a model provider;
- explicit valid opt-in reaches the real registry/reasoner and only accepted,
  cited proposals reach Candidate Hunter;
- provider and output failures preserve baseline candidates;
- Pipeline and LLM audits contain the approved metadata and no sensitive/raw
  content;
- UI model assistance is explicit, one-run, default-off, and key-free;
- every hard permission remains false;
- default release benchmark results remain unchanged; and
- no verification failure is added beyond the recorded pre-existing baseline.
