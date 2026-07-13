# TypeScript/Express Release Corpus Implementation Plan

> **Execution rule:** Every production behavior starts with a focused failing
> test. The existing 24-case corpus stays byte-for-byte unchanged. Replay is
> offline, live-provider use is explicit CLI-only, and no gate may grant
> execution, validation, candidate-promotion, or report-submission permission.

## Scope

Implement the approved design in
`docs/superpowers/specs/2026-07-13-typescript-express-release-corpus-design.md`.
Add an independent 12-development plus 12-held-out TypeScript/Express corpus,
minimal two-profile fixture loading, deterministic replay and explicit live
quality gates, answer-leakage checks, perturbation checks, and one local CLI
entry point.

Reuse the current Candidate Hunter, evidence specialist, Stage projection,
release runner, and V1 evaluator. Do not add dashboard work, a new metric,
public-target activity, automatic validation, or automatic report submission.

## Worktree and Baseline Constraints

The branch is `codex/mythos-closed-loop-summary`, and the worktree already has
hundreds of unrelated or earlier uncommitted changes. Preserve them.

- Use `apply_patch` for every source, test, fixture, and documentation edit.
- Edit only files named by the active phase.
- Never clean, reset, restore, bulk-format, or regenerate the worktree.
- Never edit `apps/api/tests/fixtures/candidate_hunter_release/` in this unit.
- Do not stage or commit pre-existing changes. If implementation commits are
  later requested, inspect and stage only attributable hunks.
- Record the full `git diff --check` baseline before implementation. It
  currently contains three unrelated entries in `.gitignore`,
  `app/deep_research/__init__.py`, and
  `app/intelligence_benchmark/release_runner.py`; introduce no new entry.

The latest verified baseline is:

- Backend: 1317 passed;
- Web: 190 passed, lint and build passed;
- Studio: 25 passed;
- Compose validation passed; and
- the planned P1 focused set: 140 passed.

Each phase must keep its focused baseline green before the next phase starts.

## Phase 0: Verified Documentation and API Boundaries

### Allowed APIs and copy-ready patterns

| Need | Existing source | Required use |
| --- | --- | --- |
| Fixture case contract | `apps/api/app/intelligence_benchmark/release_fixtures.py:35` `ReleaseFixtureCase` | Extend this one case carrier with profile-specific optional metadata; do not create a parallel loader model. |
| Suite loading | `apps/api/app/intelligence_benchmark/release_fixtures.py:45` `load_release_fixture_suite(...)` | Keep the public signature and legacy results; dispatch internally to exactly two validators. |
| Input staging | `apps/api/app/intelligence_benchmark/release_fixtures.py:107` `stage_release_fixture_inputs(...)` | Continue staging only scope, policy, API, HAR, and one `.ts` code input. |
| Delayed gold load | `apps/api/app/intelligence_benchmark/release_fixtures.py:139` `load_release_fixture_gold(...)` | Reuse the explicit post-capture oracle boundary and add new-profile validation there. |
| Real suite capture | `apps/api/app/intelligence_benchmark/release_runner.py:155` `run_candidate_hunter_release_suite(...)` | Preserve capture-all-before-gold ordering and existing legacy result shape. |
| Real case capture | `apps/api/app/intelligence_benchmark/release_runner.py:208` `_capture_candidate_hunter_release_fixture(...)` | Thread an optional per-case model runtime through this path; do not duplicate Studio intake. |
| Evidence completion | `apps/api/app/intelligence_benchmark/release_runner.py:285` `_complete_candidate_hunter_evidence_tasks(...)` | Keep the bounded existing worker loop and persisted result stages. |
| Existing metrics | `apps/api/app/intelligence_benchmark/release_v1.py:16` `METRIC_THRESHOLDS` and `:168` `evaluate_candidate_hunter_release_suite_v1(...)` | Reuse all six formulas and thresholds unchanged. |
| Safety evaluation | `apps/api/app/intelligence_benchmark/release_v1.py:681` `_safety_failures(...)` and `:825` `_permission_failure_reason(...)` | Add candidate-promotion to the same forced-false safety contract. |
| Replay reasoner | `apps/api/app/cross_source_candidate_generator.py:163` `ReplayCandidateReasoner(payload)` | Feed a parsed synthetic response through the real schema and proposal validator without a registry or network. |
| Live reasoner | `apps/api/app/cross_source_candidate_generator.py:178` `RegistryCandidateReasoner(registry)` | Keep real calls on the existing deterministic request path only. |
| Model configuration | `apps/api/app/cross_source_candidate_generator.py:40` `CandidateModelConfig` | Reuse provider/model validation. It remains live-only and is not exposed to a replay provider value. |
| Studio integration | `apps/api/app/main.py:2641` `run_mythos_studio_workspace_research(...)` | Extract a narrow internal service so the release runner can inject replay; leave the FastAPI request contract unchanged. |
| LLM audit | `apps/api/app/repository.py:172` `save_llm_run(...)` | Store only safe provider/model/mode/hash/latency/error/safety-note metadata. Its `mode` argument accepts a safe string. |
| TypeScript facts | `apps/api/app/codebase_map/__init__.py:1171` `_map_typescript_express_file(...)` | Author fixtures using its documented Router/app, handler, middleware, boundary comparison, service call, sensitive sink, and public-filter patterns. |
| Candidate observations | `apps/api/app/candidate_hunter_loop.py:34` `build_candidate_hunter_observations(...)` | Let observed facts decide retain/refute/deduplicate/suppress; never encode a terminal decision in staged inputs. |
| Durable projection | `apps/api/app/candidate_hunter_loop.py:1497` `load_candidate_hunter_projection(...)` | Continue treating persisted immutable Stages as the normalized-output authority. |
| Evidence specialist | `apps/api/app/candidate_hunter_evidence.py:42`, `:134`, and `:214` | Reuse materialize, inspect, and resume behavior; `.ts` is already an authorized source suffix. |
| CLI pattern | `apps/api/app/cli.py:35` `main(...)` and `:267` `run_candidate_hunter_release_eval_command(...)` | Copy argparse, JSON-output, and status-based exit-code behavior. |
| CLI documentation | `README.md:44-46` and `:116-141` | Document `python -m app`; do not claim an installed global command. |
| Fixture tests | `apps/api/tests/test_candidate_hunter_release_fixtures.py:33`, `:125`, `:340`, and `:429` | Copy balanced-corpus, answer-leakage, perturbation, and delayed-gold test patterns. |
| Runner tests | `apps/api/tests/test_candidate_hunter_release_runner.py:143`, `:189`, and `:237` | Copy event-order, complete-suite, and invalid-Stage fail-closed patterns. |
| Model tests | `apps/api/tests/test_cross_source_candidate_generator.py:149` and `apps/api/tests/test_studio_api.py:2921` | Copy fact-bound replay/registry proposal and safe audit assertions. |

### APIs and shortcuts that do not exist

- `LLMMode` has only `dry_run` and `live`; do not add or assume an external
  `replay` provider/mode.
- `ProviderName` has only `openai`, `claude`, and `deepseek`; do not expose a
  replay provider through the Studio API or Web UI.
- The current Studio route has no reasoner-injection parameter; add an internal
  service boundary, not a FastAPI request field.
- The current fixture loader supports one declared `.ts` file per case; do not
  expand this unit into multi-file project ingestion.
- There is no full-suite release-run CLI yet. Add one narrow gate command; do
  not reuse the pure `candidate-hunter-release-eval` command for workspace runs.

### Approved internal contracts

New manifest identity:

```json
{
  "profile": "candidate_hunter_typescript_express",
  "version": "candidate_hunter_typescript_express_fixture_v1"
}
```

The loader's internal profile names are exactly
`candidate_hunter_release_legacy` for the existing version-only manifest and
`candidate_hunter_typescript_express` for the new manifest. These names are
loader metadata, not staged inputs.

New manifest entries contain exactly:

```text
case_id
suite
authorization_pattern
path
```

New `case.json` contains exactly its case ID, the four existing safety
declarations, and five input declarations. Only `gold.json` contains expected
dispositions, roots, evidence, refutations, and duplicate relationships.

Add one internal runner runtime, not a public API model:

```python
@dataclass(frozen=True)
class ReleaseCaseModelRuntime:
    provider: ProviderName
    model: str
    reasoner: CandidateReasoner | None
    audit_mode: Literal["live", "replay"]
```

Legacy calls omit it and stay baseline-only. Replay uses the existing
`ReplayCandidateReasoner`, a fixed internal `ProviderName.OPENAI` schema value,
model name `fixture-replay-v1`, audit mode `replay`, and no registry. The audit
mode and a `synthetic_replay_no_provider_call` safety note make clear that the
provider field did not represent a live call. Gate results omit provider/model
for replay.

The new orchestration entrypoint is:

```python
run_candidate_hunter_typescript_release_gate(
    *,
    fixture_root: Path,
    workspace_root: Path,
    session: Session,
    mode: Literal["replay", "live"],
    provider: ProviderName | None = None,
    model: str | None = None,
) -> dict[str, Any]
```

Replay rejects provider/model arguments. Live requires both. The function
always runs development first and does not open release replay/gold files,
create release workspaces, or call a release provider unless development
passes.

### Phase 0 anti-pattern guards

- Do not derive gold or replay responses from current Candidate Hunter output.
- Do not alter a metric threshold, matching rule, or legacy fixture to make the
  new gate pass.
- Do not persist prompts, raw responses, code bodies, headers, cookies, tokens,
  API keys, or authorization material.
- Do not add retry, provider fallback, model voting, a global replay switch, or
  a caller-selected fixture root to the CLI.
- Do not let a safe baseline fallback qualify a replay or live model run.

## Phase 1: Lock Legacy Behavior and Complete the Promotion Safety Contract

### Files

- Add `apps/api/tests/test_candidate_hunter_typescript_release_fixtures.py`.
- Update `apps/api/tests/test_candidate_hunter_release_benchmark.py`.
- Update `apps/api/tests/test_candidate_hunter_release_runner.py`.
- Update `apps/api/app/intelligence_benchmark/release_v1.py`.
- Update `apps/api/app/intelligence_benchmark/release_runner.py` only in the
  observed-field normalizer.

### Documentation references

- Copy the current tree iteration and opaque-case assertions from
  `test_candidate_hunter_release_fixtures.py:33-221`.
- Extend the existing permission parameterizations at
  `test_candidate_hunter_release_benchmark.py:280-370`.
- Extend the current final-candidate permission loop and normalized recursive
  field map at `release_v1.py:681-720` and `:796-830`.

### RED tests

1. Compute one deterministic SHA-256 tree digest from relative paths plus file
   bytes under the legacy fixture root and hard-code the current digest. Require
   it to stay unchanged throughout this unit.
2. Add `candidate_promotion_allowed=False` to the valid normalized-output test
   factory.
3. Add failures for candidate promotion set to `True`, missing, `None`, and the
   string `"false"`. Require `candidate_promotion_allowed_true` or
   `candidate_promotion_allowed_not_false`.
4. Extend the existing normalizer input with an observed top-level
   `candidate_promotion_allowed=False` and require that exact field in the
   normalized candidate. Add a negative case proving the normalizer does not
   invent it when the source candidate omits it.
5. Run the focused test and confirm RED is only the missing promotion safety
   check. The legacy tree-digest guard should already pass.

### GREEN implementation

1. Add `candidate_promotion_allowed` to `_safety_failures()` beside execution,
   validation, and report submission.
2. Add normalized key `candidatepromotionallowed` to the recursive permission
   field map.
3. Extend `normalize_studio_candidates_for_release_v1()` with one observed-only
   mapping for `candidate_promotion_allowed`. Do not synthesize a default.
4. Do not change any metric, root matcher, decision evaluator, or threshold.

### Verification checklist

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_candidate_hunter_release_benchmark.py `
  tests/test_candidate_hunter_release_runner.py `
  tests/test_candidate_hunter_release_fixtures.py `
  tests/test_candidate_hunter_typescript_release_fixtures.py -q
```

- Confirm the legacy fixture tree digest matches.
- Confirm both current legacy 12-case suite tests still pass.
- Confirm all six metric values and thresholds remain unchanged.

### Anti-pattern guards

- Do not add dispatch permission to the V1 evaluator in this unit.
- Do not edit normalized-output fields unrelated to candidate promotion.
- Do not touch the legacy fixture root.

## Phase 2: Add Explicit Two-Profile Fixture Loading

### Files

- Update `apps/api/tests/test_candidate_hunter_typescript_release_fixtures.py`.
- Update `apps/api/app/intelligence_benchmark/release_fixtures.py`.

### Documentation references

- Copy `_copied_fixture_root`, `_manifest_entry`, path-escape, unsafe-metadata,
  and TypeScript-only patterns from
  `test_candidate_hunter_release_fixtures.py:18-32` and `:450-580`.
- Keep `stage_release_fixture_inputs(...)` and `_input_specs(...)` as the only
  staged-input authority.

### RED tests

Use a small test-only builder under `tmp_path` to create 24 minimal new-profile
case directories. Do not use production output to build them.

1. Require exact profile/version detection and rejection of unknown values.
2. Require 24 unique IDs/paths, 12 cases per suite, and four manifest entries
   for each of `object_ownership`, `tenant_boundary`, and `role_boundary` in
   each suite.
3. Require exact top-level manifest and entry keys. Reject
   `expected_disposition`, `risk_family`, gold IDs, duplicate labels, or unknown
   fields in the new manifest.
4. Require the new `case.json` to omit `risk_family` and
   `expected_disposition`, match the manifest case ID, contain the four exact
   safety values, and declare all five existing input kinds.
5. Require new cases to expose profile and authorization-pattern metadata but
   no pre-capture disposition. Legacy cases must still expose their current
   risk-family and disposition strings.
6. Require new-profile loading to materialize only the requested suite's case
   files after global manifest validation.
7. Require unknown profile, wrong count, duplicate ID/path, invalid pattern,
   path escape, unsafe metadata, and oracle fields in staged inputs to fail
   closed with stable safe reasons.

Run the new tests and confirm they fail against the hard-coded legacy parser.

### GREEN implementation

1. Add exact legacy and TypeScript/Express profile constants.
2. Extend `ReleaseFixtureCase` narrowly with profile and optional
   authorization-pattern metadata. Keep legacy risk-family and disposition
   values unchanged; new cases expose neither before gold.
3. Split manifest parsing into two explicit validators selected by the legacy
   version or the exact new profile/version. Do not create a plugin registry.
4. For the new profile, reject unknown keys and oracle-bearing fields and load
   only entries for the requested suite after validating the global 12-plus-12
   matrix.
5. Keep legacy parsing, error reasons, sorting, and returned values unchanged.
6. Apply the existing containment, secret-text, TypeScript suffix, exact-input,
   and safety-declaration checks to both profiles.
7. Add a new-profile staged-input oracle-leak check for disposition words and
   reserved gold field names. Do not scan model output as source input.

### Verification checklist

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_candidate_hunter_release_fixtures.py `
  tests/test_candidate_hunter_typescript_release_fixtures.py -q
```

- Run each invalid-profile test alone once to verify the intended RED/GREEN
  reason.
- Re-run the legacy tree-digest and complete-balanced-corpus tests.
- Inspect `git diff` and confirm no legacy fixture file changed.

### Anti-pattern guards

- Do not make `EXPECTED_CASE_COUNT`, risk families, or dispositions globally
  permissive.
- Do not infer a profile from a directory name.
- Do not read gold while constructing a new `ReleaseFixtureCase`.
- Do not add configuration for hypothetical third profiles.

## Phase 3: Author the Independent 24-Case Inputs and Gold Oracles

### Files

- Add `apps/api/tests/fixtures/candidate_hunter_typescript_release/suite-manifest.json`.
- Add 24 `case.json` files and 120 input files under
  `apps/api/tests/fixtures/candidate_hunter_typescript_release/cases/`.
- Add 24 `gold.json` files beside those cases.
- Update `apps/api/tests/test_candidate_hunter_typescript_release_fixtures.py`.
- Update `apps/api/app/intelligence_benchmark/release_fixtures.py` only for
  post-capture gold-set validation.

### Documentation references

- Copy file schemas, never scenario contents, from
  `apps/api/tests/fixtures/candidate_hunter_release/cases/case-001/` through
  `case-004/`.
- Author Express syntax supported by
  `codebase_map/__init__.py:1171-1487`: named handlers, Router/app route calls,
  direct or router middleware, ownership/tenant comparisons, role comparisons,
  shared service calls, supported sensitive sinks, and `visibility: "public"`.
- Copy gold shape and evidence-ref rules from
  `test_candidate_hunter_release_fixtures.py:380-427` and
  `release_v1.py:399-496`.

### Fixed coverage map

The manifest declares only suite and authorization pattern. The disposition
below exists only in the corresponding gold file.

| Cases | Suite | Pattern | Gold outcomes in numeric order |
| --- | --- | --- | --- |
| `tse-001`-`tse-004` | development | object ownership | retain, refute, deduplicate, suppress |
| `tse-005`-`tse-008` | development | tenant boundary | retain, refute, deduplicate, suppress |
| `tse-009`-`tse-012` | development | role boundary | retain, refute, deduplicate, suppress |
| `tse-013`-`tse-016` | release | object ownership | retain, refute, deduplicate, suppress |
| `tse-017`-`tse-020` | release | tenant boundary | retain, refute, deduplicate, suppress |
| `tse-021`-`tse-024` | release | role boundary | retain, refute, deduplicate, suppress |

Directories remain `case-001` through `case-024`. IDs, directories, opaque
scenario tokens, routes, operation IDs, symbols, and workspace names must not
encode the outcome.

### RED tests

1. Point the new test module at the approved fixture root and require the exact
   12-plus-12 and 3-by-4 matrix. Confirm RED because the root does not exist.
2. Require every case to have the five A+B inputs, an opaque unique scenario
   token unrelated to its case ordinal, local-only scope, and one `.ts` Express
   file.
3. Require no external URL, case identity, disposition word, gold field,
   credential/cookie/token marker, or real-user-data marker in any staged
   input or path.
4. Map every `code.ts` with `map_authorized_code_files(...)` and require:
   - retain: one gap and no decisive/public control;
   - refute: one gap plus the pattern-appropriate owner, tenant, or role fact;
   - deduplicate: two route gaps reaching one shared service root; and
   - suppress: one gap plus an observed public filter while scope remains
     allowed.
5. Require development and release cases for the same matrix cell to have
   different route shape, handler/service arrangement, resource token, and
   source digest. Reject rename-only pairs.
6. Require every gold route and evidence/refutation ref to be observable in
   its five inputs.
7. Require every gold root to have `scope_allowed=true`. A deduplicate case has
   exactly one retained canonical root and one duplicate root; other cases have
   exactly one root of their outcome.
8. Require `authorization_pattern` in gold to match the manifest, and require
   all four classified outcomes for every pattern in each suite.

These gold checks are static authoring lint and do not run Candidate Hunter.
The runtime gate remains forbidden from opening gold before its suite capture
completes.

### GREEN fixture authoring and loader work

1. Write all files as static synthetic fixtures. Do not add a generator script.
2. Use different neutral domains and control layouts between development and
   release. Keep every example inside the extractor's supported one-hop slice.
3. Use relative HAR routes or empty sanitized HAR entries; never add a host.
4. Keep API route templates aligned with Express parameter routes and use
   stable `code:code.ts:<symbol>` and `api:<METHOD>:<path>` refs.
5. Put no disposition or root label outside gold.
6. Extend explicit gold loading for the new profile to require the matching
   authorization pattern and safe oracle shape.
7. Add `load_release_fixture_gold_suite(cases)` that loads only after capture,
   classifies the gold outcome, validates the exact 3-by-4 matrix, and returns
   gold in case order. For legacy cases it delegates to the existing per-case
   loader without changing evaluation data.

### Verification checklist

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_candidate_hunter_typescript_release_fixtures.py `
  tests/test_candidate_hunter_release_fixtures.py `
  tests/test_codebase_map.py `
  tests/test_candidate_hunter_loop.py -q
```

- Inspect every gold ref mismatch reported by the test; fix the fixture, never
  weaken the matcher.
- Confirm each suite produces nonzero expected retained, refute, duplicate,
  suppress, evidence, and human-worth categories.
- Confirm the legacy tree digest remains unchanged.

### Anti-pattern guards

- Do not copy or rename a development case into release.
- Do not name a function `unguarded`, `missing_owner_check`, `retain`, or any
  other answer label.
- Do not use out-of-scope roots for suppression; V1 requires
  `scope_allowed=true`.
- Do not manufacture a gold ref that the extractor does not emit.

## Phase 4: Add Safe Replay Responses and Suite Preflight

### Files

- Add 24 `replay/response.json` files under the new cases.
- Update `apps/api/tests/test_candidate_hunter_typescript_release_fixtures.py`.
- Update `apps/api/app/intelligence_benchmark/release_fixtures.py`.

### Documentation references

- Copy the exact response/proposal schema from
  `test_cross_source_candidate_generator.py:83-113`.
- Reuse `ReplayCandidateReasoner(payload)` and the real proposal checks at
  `cross_source_candidate_generator.py:741-788`.
- Reuse current secret/path text checks in `release_fixtures.py`; do not create
  a second safety scanner.

### RED tests

1. Require exactly one replay response outside `inputs/` for every case.
2. Require valid `cross_source_candidate_model_v1` JSON with one proposal for
   retain/refute/suppress and two route proposals for deduplicate.
3. Require every proposal to cite only observed allowed refs, cite its affected
   route, cite `code.ts` and API or HAR, and use an observed code symbol.
4. Require no expected disposition, gold ID, duplicate relation, unsafe claim,
   secret-shaped content, real-user marker, or permission field in replay.
5. Require `preflight_release_fixture_suite(cases)` to validate manifest/case,
   all staged inputs, and replay files for only that suite without opening
   gold.
6. Instrument `load_release_fixture_gold` and require zero calls during
   preflight.
7. Require missing, invalid JSON, unsafe, path-escaped, wrongly named, or extra
   replay files to fail before workspace creation.

### GREEN implementation

1. Author static fact-bound replay payloads. Root summaries and code paths must
   match observed gap roots so baseline and model proposals merge when they
   describe the same candidate.
2. Add `load_release_fixture_replay(case) -> dict[str, Any]` with containment,
   JSON-object, and existing safety-text checks. Do not run the proposal schema
   validator here; the real reasoner path must still prove it.
3. Add `preflight_release_fixture_suite(cases)` that stages all five inputs and
   loads replay for the requested suite only. It never loads gold or creates a
   workspace.
4. Keep replay files out of `case.json` input declarations and actual staged
   file enumeration.

### Verification checklist

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_candidate_hunter_typescript_release_fixtures.py `
  tests/test_cross_source_candidate_generator.py -q
```

- Confirm an intentionally invalid response reaches RED through the real
  `ReplayCandidateReasoner`, not through a fixture-specific shortcut.
- Confirm preflight records no pipeline run, workspace, Stage, or LLM audit.
- Confirm no registry factory is called.

### Anti-pattern guards

- Do not store a rendered prompt or a provider wrapper response.
- Do not mark replay as a live provider call.
- Do not accept a fixture response merely because it matches gold.
- Do not stage replay as source evidence.

## Phase 5: Thread Replay Through the Real Studio and Release Runner

### Files

- Update `apps/api/tests/test_studio_api.py` narrowly.
- Update `apps/api/tests/test_candidate_hunter_release_runner.py`.
- Add `apps/api/tests/test_candidate_hunter_typescript_release_gate.py`.
- Update `apps/api/app/main.py` narrowly around the Studio run function.
- Update `apps/api/app/intelligence_benchmark/release_runner.py`.

### Documentation references

- Copy enabled model request, fact-bound provider, no-raw-audit, and forced-
  false permission assertions from `test_studio_api.py:2921-3393`.
- Copy suite event-order and real evidence completion from
  `test_candidate_hunter_release_runner.py:143-233`.
- Keep `StudioWorkspaceRunRequest` and `StudioCandidateModelRequest` unchanged.

### RED tests

1. Add an internal-service test that supplies an enabled existing-provider
   request plus `ReplayCandidateReasoner`. Require completed model generation,
   accepted proposals, audit mode `replay`, the replay safety note, no registry
   construction, and no raw response persistence.
2. Wrap replay with a recording test reasoner and inspect the received Fact
   Pack. Require no case ID, suite, authorization-pattern control field,
   manifest field, replay payload, expected disposition, gold ID, or duplicate
   oracle metadata.
3. Require replay override with a disabled/missing candidate-model request to
   fail before persistence. Require audit mode `replay` without an injected
   reasoner to fail rather than call a provider.
4. Require the public FastAPI route, default-off request, and live registry path
   to return exactly their current contracts.
5. Add `ReleaseCaseModelRuntime` and optional case/suite runner arguments to
   tests. Omission must produce the current baseline-only request byte for byte.
6. Run one new-profile replay case through real Studio intake, Candidate Hunter,
   evidence inspection, resume, projection, and delayed gold evaluation.
7. Require `candidate_generation.model_status=completed`,
   `accepted_count>=1`, all four hard permissions false, two Hunter rounds,
   immutable Stage audit ready, and submission blocked.
8. Spy on suite capture/gold calls and require all 12 captures before the first
   gold load.
9. Require a malformed replay to remain safe and expose
   `model_status=needs_model_review` even if baseline candidates satisfy
   evaluator metrics. Phase 6 turns that observed signal into a gate failure.

### GREEN implementation

1. Extract the body of `run_mythos_studio_workspace_research(...)` into one
   private async service with keyword-only `reasoner_override` and
   `audit_mode`. The FastAPI route delegates with no overrides.
2. Preserve current live behavior when no override is supplied. Accept replay
   only through the internal service, require an enabled model request, and
   never expose the override through Pydantic, FastAPI, or Web types.
3. Save replay audit rows with `mode="replay"` and
   `synthetic_replay_no_provider_call`; retain prompt-hash-only and no-raw
   safety notes. Do not change `CandidateModelConfig.mode` or the public
   `LLMMode` enum.
4. Add `ReleaseCaseModelRuntime` to `release_runner.py` and an optional
   `model_runtime_factory(case)` to case/suite capture. Default `None` preserves
   legacy behavior.
5. Build the enabled Studio request from the runtime, pass a replay reasoner
   only for replay, and call the new private Studio service from the existing
   sync wrapper.
6. Replace the suite's post-capture per-case gold list with
   `load_release_fixture_gold_suite(cases)` while preserving the legacy result
   keys and event list.

### Verification checklist

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_studio_api.py `
  tests/test_cross_source_candidate_generator.py `
  tests/test_candidate_hunter_release_runner.py `
  tests/test_candidate_hunter_typescript_release_gate.py `
  tests/test_candidate_hunter_evidence.py `
  tests/test_candidate_hunter_loop.py -q
```

- Query LLM and Pipeline audit records and serialize them with the API response;
  assert replay source JSON, prompt text, source bodies, and secret field names
  are absent.
- Confirm default Studio tests still prove the registry is not constructed.
- Confirm the existing legacy suite metrics still pass.

### Anti-pattern guards

- Do not add a replay field to `StudioWorkspaceRunRequest`.
- Do not monkeypatch a production registry or use environment variables to
  select replay.
- Do not turn replay parse failure into a passing baseline gate.
- Do not duplicate the Studio research body in `release_runner.py`.

## Phase 6: Implement the Sequential Replay and Live Quality Gate

### Files

- Add `apps/api/app/intelligence_benchmark/typescript_release_gate.py`.
- Update `apps/api/tests/test_candidate_hunter_typescript_release_gate.py`.

### Documentation references

- Reuse `load_release_fixture_suite(...)`,
  `preflight_release_fixture_suite(...)`, and
  `run_candidate_hunter_release_suite(...)` from prior phases.
- Reuse the suite evaluator result unchanged; add orchestration failures around
  it instead of changing metrics.
- Copy safe diagnostic projection style from the existing release evaluator's
  `case_diagnostics`, `schema_failures`, and `safety_failures`.

### RED tests

1. Require replay mode to reject provider/model and live mode to require an
   allowed provider plus nonblank model.
2. Require development preflight and execution before any release fixture
   replay/gold/workspace/provider access.
3. Force a development metric, Stage, safety, or model-runtime failure and
   require `release_attempted=false`, overall failure, and no release calls.
4. Require each attempted case to have model requested, model status completed,
   at least one accepted proposal, ready loop audit, and all four hard
   permissions false. Baseline fallback must fail this orchestration gate.
5. Run the actual 12 development replay cases, then the actual 12 release replay
   cases. Require all six existing thresholds, positive denominators, no Stage
   audit failure, and overall pass.
6. Monkeypatch `build_default_registry` to raise during the replay gate and
   require the full gate still passes with zero network/provider construction.
7. For live mode, inject a safe fake registry in tests and require provider and
   model to flow to the current registry reasoner. Provider timeout, missing key,
   invalid response, or zero accepted proposals must fail qualification even
   when baseline evaluation passes.
8. Serialize the gate result and require no workspace path, source body, prompt,
   raw response, key/token/cookie/header, or gold payload.

### GREEN implementation

1. Add exact gate/profile/version constants and the approved function signature.
2. Implement separate explicit replay and live runtime factories:
   - replay loads the case response and injects `ReplayCandidateReasoner`;
   - live supplies the requested provider/model with no override so the private
     Studio service uses `RegistryCandidateReasoner(build_default_registry())`.
3. Preflight and run development. Combine evaluator status with safe per-case
   model, Stage, and permission audit failures.
4. Return immediately on development failure without loading or running the
   release suite.
5. Only after development passes, preflight and run release and apply the same
   checks.
6. Return versioned safe metadata:
   - profile/version and mode;
   - overall status;
   - development/release attempted and status;
   - provider/model only for live;
   - existing metric details;
   - safe case IDs and diagnostic reasons;
   - model/Stage/oracle-order/safety failures; and
   - `release_qualified=true` only for a passing live pair.
7. Do not return raw `case_runs`, workspace paths, prompts, responses, Fact
   Packs, or gold objects.

### Verification checklist

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_candidate_hunter_typescript_release_gate.py `
  tests/test_candidate_hunter_release_runner.py `
  tests/test_candidate_hunter_release_benchmark.py -q
```

- Record the exact six development and release metric values.
- Assert release was not attempted in every parameterized development failure.
- Inspect repository LLM rows: replay rows are mode `replay`; live fake rows are
  mode `live`; neither contains raw content.

### Anti-pattern guards

- Do not describe replay success as live model quality.
- Do not qualify a provider family; qualification is the exact provider/model
  pair only.
- Do not continue to held-out release after development failure.
- Do not catch infrastructure errors and turn them into passing metrics.

## Phase 7: Add Perturbation Proof, Explicit CLI, and Operator Documentation

### Files

- Update `apps/api/tests/test_candidate_hunter_typescript_release_gate.py`.
- Update `apps/api/tests/test_candidate_hunter_release_benchmark.py` or add CLI
  tests to the new gate test module, whichever keeps the assertions local.
- Update `apps/api/app/cli.py`.
- Update `README.md`.

### Documentation references

- Copy manifest reorder and case-ID replacement mechanics from
  `test_candidate_hunter_release_fixtures.py:340-379`.
- Copy CLI JSON output and exit-code assertions from
  `test_candidate_hunter_release_benchmark.py:625-673`.
- Copy local invocation wording from `README.md:44-46`.

### RED tests

1. Copy the new corpus to `tmp_path`, assign new opaque IDs, rename case
   directories, rewrite manifest/case references, and reverse manifest order.
2. Run the deterministic gate on original and perturbed roots. Compare the six
   metrics, semantic root/disposition results, Stage/safety status, and pass
   state using the test's old-to-new case map. Exclude workspace/run UUIDs.
3. Add parser tests for:

   ```text
   candidate-hunter-typescript-gate
     --mode replay|live
     [--provider openai|claude|deepseek]
     [--model MODEL]
     [--output PATH]
   ```

4. Require `--mode` explicitly. Replay rejects provider/model. Live requires
   both. No `--api-key`, `--fixture-root`, `--workspace-root`, or release-only
   bypass exists.
5. Mock only the gate function in CLI unit tests. Require safe JSON output, zero
   only for pass, one for quality/runtime failure, and two for invalid mode
   configuration.
6. Require the default replay CLI path to create a temporary local database and
   workspace root and to delete them after the command. No default path may call
   a provider.
7. Require README examples to show replay and explicit live invocations and to
   state that keys come only from backend environment variables.
8. Raise a fixture, runner, filesystem, and database infrastructure error from
   the mocked gate. Require exit one and a generic safe error category without
   exception text, paths, source content, or credentials.

### GREEN implementation

1. Add the one argparse subcommand and conditional configuration validation.
2. Derive the fixed repository fixture root from the local `apps/api` package;
   do not accept it from the caller.
3. Use a temporary directory, temporary SQLite database, existing
   `ensure_database_schema(...)`, and one SQLAlchemy session for the complete
   gate.
4. Emit only the safe gate result to stdout or `--output` and use the approved
   exit codes.
5. Update README with exact `python -m app` commands, synthetic-corpus scope,
   replay/live meaning, provider/model qualification boundary, and the explicit
   no-auto-validation/no-auto-submission warning.
6. Catch only the known fixture, runner, filesystem, and SQLAlchemy
   infrastructure exceptions at the CLI boundary. Emit a generic safe failure
   result and nonzero exit; do not convert programmer assertions or schema-test
   failures into success.

### Verification checklist

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_candidate_hunter_typescript_release_gate.py `
  tests/test_candidate_hunter_release_benchmark.py `
  tests/test_cli_entrypoint.py -q

..\..\.venv\Scripts\python.exe -m app candidate-hunter-typescript-gate `
  --mode replay `
  --output ..\..\tmp\typescript-release-gate.json
```

- Inspect the generated result, then remove only that explicitly named
  verification artifact.
- Confirm the command makes no network call and reports replay, not live
  qualification.
- Confirm perturbation produces identical semantic results.

### Anti-pattern guards

- Do not execute a real live provider during automated tests or repository
  completion verification.
- Do not infer live mode from API-key environment variables.
- Do not add a release-only CLI flag that bypasses development.
- Do not retain temporary workspaces, databases, prompts, or raw responses.

## Phase 8: Full Verification and Handoff

### Documentation references

- Use the repository commands already established in the prior Studio reasoner
  and release benchmark plans.
- Compare against the baseline recorded above, not against assumptions about a
  clean worktree.

### Verification sequence

1. Run the focused new profile, loader, runner, evaluator, reasoner, Studio,
   evidence, loop, and CLI tests together.
2. Run the entire backend suite and record the exact new pass count.
3. Run Web tests/lint/build and Studio tests even though this unit has no UI
   change.
4. Run Compose configuration validation.
5. Run the replay CLI once with an explicitly named temporary output, inspect
   only safe metadata, and remove that output.
6. Run `git diff --check` and compare with the three-entry pre-implementation
   baseline. Run scoped whitespace checks on every new file and require zero
   new issue.
7. Search the new fixture root and changed audit/result code for external URLs,
   secret-shaped values, raw prompts/responses, and permission assignments to
   `True`.
8. Inspect `git status --short`; confirm no legacy fixture, authorized package,
   live output, database, workspace, test result, or temporary artifact was
   added by this unit.

### Final commands

```powershell
Set-Location apps/api
..\..\.venv\Scripts\python.exe -m pytest `
  tests/test_candidate_hunter_typescript_release_fixtures.py `
  tests/test_candidate_hunter_typescript_release_gate.py `
  tests/test_candidate_hunter_release_fixtures.py `
  tests/test_candidate_hunter_release_runner.py `
  tests/test_candidate_hunter_release_benchmark.py `
  tests/test_cross_source_candidate_generator.py `
  tests/test_candidate_hunter_evidence.py `
  tests/test_candidate_hunter_loop.py `
  tests/test_studio_api.py `
  tests/test_cli_entrypoint.py -q

..\..\.venv\Scripts\python.exe -m pytest -q

Set-Location ..\web
npm test
npm run lint
npm run build

Set-Location ..\studio
npm test

Set-Location ..\..
docker compose -f infra/docker-compose.yml config --quiet
git diff --check
git status --short
```

### Final anti-pattern guards

- A replay pass proves repository behavior, not live model quality.
- Do not run the live CLI merely to complete implementation.
- Do not weaken gold, replay, schema, metric, Stage, or permission checks to
  make verification green.
- Do not clean or overwrite unrelated dirty-worktree content.

## Completion Evidence

This unit is complete only when:

- the legacy fixture tree digest and existing suite results are unchanged;
- the new root has 12 development and 12 release cases with all three patterns
  and four outcomes per pattern;
- every staged input is synthetic, authorized, offline, secret-free, and free
  of oracle/disposition metadata;
- every replay proposal passes the real schema and fact-reference validator and
  at least one proposal is accepted per case;
- development passes before release is touched;
- gold is loaded only after every candidate and immutable Stage in its suite is
  captured;
- both replay suites meet the six existing thresholds with positive
  denominators and no hard safety or Stage failure;
- replay never constructs a provider or makes a network call;
- case-ID, directory, and manifest-order perturbation preserves semantic
  outcomes;
- live mode is explicit CLI-only and qualification is tied to the exact
  provider/model pair;
- execution, validation, candidate promotion, and report submission remain
  false everywhere;
- Backend, Web, Studio, and Compose verification passes; and
- no new full-diff whitespace error or unrelated worktree change is introduced.
