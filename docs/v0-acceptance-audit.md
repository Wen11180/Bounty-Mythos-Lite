# V0 Acceptance Audit

Date: 2026-07-07

This audit checks the current implementation against `docs/final-proposal-development-plan.md`.
It is intentionally conservative: an item is marked complete only when there is direct code or
test evidence in the current project.

## Scope

V0 covers the local source audit workbench only:

`local repo + scope file -> source audit scan -> pipeline run -> artifact/provenance -> validation workspace -> report preview -> manual observation -> claim review -> finding candidate`

Out of scope for V0:

- Public target scanning.
- Automatic exploit or payload execution.
- Automatic report submission.
- Treating scanner, LLM, or imported third-party output as a confirmed vulnerability.
- Saving raw secrets, cookies, tokens, authorization headers, or real user data.

## Acceptance Matrix

| Requirement | Status | Evidence | Remaining Work |
| --- | --- | --- | --- |
| Local repo must be allowlisted before scan | Complete | `apps/api/tests/test_source_audit.py` covers unallowlisted repo blocking and no pipeline run creation. | None for V0. |
| Missing or unauthorized local repo fails closed | Complete | `test_run_source_audit_blocks_unallowlisted_repo_before_semgrep` proves Semgrep is not called after scope block. | Add a dedicated API test for non-existent repo if the API should expose a distinct error. |
| Scan reads local source metadata only | Complete | Source audit tests assert raw source snippets like `send_file(file_id)` do not appear in report, payload, detail, or candidate responses. | Keep expanding leak checks as new artifact types are added. |
| Intake identifies supported stacks | Complete | Source audit tests cover Python, TypeScript/JavaScript, Go, FastAPI, Next.js, and manifest discovery. | Add more framework fixtures only when needed by real targets. |
| Dependency handling is manifest summary only | Complete | Tests assert manifest counts and package summaries without CVE promotion. | None for V0. |
| Semgrep failure or absence is non-fatal | Complete | `run_semgrep` tests cover JSON normalization and wrapper behavior; source audit supports skipped status. | Keep CLI environment failures covered when packaging. |
| CodeQL remains skipped/not configured unless injected | Complete | Tests assert injected and skipped CodeQL states. | Real CodeQL execution belongs outside the V0 acceptance gate. |
| Findings are hypotheses, not verified vulnerabilities | Complete | Finding JSON and report preview tests assert `unverified_hypothesis`, human review requirements, readiness blockers, `refutation_status`, `false_positive_checks`, `priority_score`, and `ranking_reasons`. | Keep later Phase 3 work advisory unless a human promotes evidence. |
| Report draft is submission blocked | Complete | API source audit tests assert report preview `submission_blocked`; source audit payload records `report_draft.auto_submit_allowed == false`. | None for V0. |
| Scan persists as auditable pipeline run | Complete | Source audit API and repository tests assert pipeline run creation, artifact id, timeline, validation gate, and report preview. | Browser-level E2E remains pending. |
| Artifact provenance links scan, evidence bundle, and report claims | Complete | Source audit persistence tests assert artifact usage records for `pipeline_run`, `evidence_bundle`, and `report_claim`. | Add UI display checks if artifact detail becomes part of the V0 demo path. |
| Validation workspace is human gated | Complete | Tests assert `allowed_to_execute == false`, `human_approved == false`, claim tasks require review, and manual observations use report-safe evidence refs. | None for V0. |
| Finding candidate requires manual evidence and claim review | Complete | API test covers blocked promotion before manual observation and claim review, then successful candidate creation after both gates. Web helper smoke covers the same sequence without validation, approval, or submission calls. | Browser-level E2E remains pending. |
| Report submission remains manual after candidate creation | Complete | API test asserts candidate promotion does not set auto submission; report draft keeps `auto_submit_allowed == false`. | No automatic submission endpoint should be added without a separate human-gated design. |
| Web source audit entrypoint is local and human gated | Complete | Web tests assert `/source-audit` posts only local repo/scope inputs and contains no validation, finding promotion, or submission actions. | Browser-level E2E is pending. |
| Web report preview records claim review manually | Complete | Web tests assert claim review form and API helper exist and avoid validation/submission actions; helper smoke sequences it after source audit and manual observation. | Browser-level E2E remains pending. |
| Web validation workspace records safe manual observation | Complete | Web tests assert safe observation types, safety notes, no hardcoded unsafe observation path, and helper smoke sequences observation before claim review. | Browser-level E2E remains pending. |
| Phase 3 refutation and ranking metadata is carried end-to-end | Complete for the current narrow slice | API tests assert `unverified`, `parked`, and `refuted` classification plus `false_positive_checks`, `priority_score`, and `ranking_reasons`; Web tests assert run detail, report preview, and dashboard expose the state read-only. | Deeper semantic audit heuristics and browser-level confirmation remain outside this slice. |
| Service-layer authorization reduces false-positive hypotheses | Complete for the current narrow slice | `apps/api/tests/test_codebase_map.py` covers route-to-service authz mapping; `apps/api/tests/test_source_audit.py` covers `run_source_audit` not raising an authorization hypothesis when the called service performs ownership/role authorization before a sensitive sink. | Extend to aliasing and multi-hop service calls in later Phase 3 slices. |
| Dependency-injected route authorization reduces false-positive hypotheses | Complete for the current narrow slice | `test_map_authorized_code_files_treats_dependency_injected_authz_as_route_authz` covers same-line FastAPI `Depends(require_user)` in handler signatures; `test_map_authorized_code_files_treats_multiline_signature_dependency_authz_as_route_authz` covers multi-line handler signatures; `test_map_authorized_code_files_treats_decorator_dependency_authz_as_route_authz` covers same-line route decorator `dependencies=[Depends(require_user)]`; `test_map_authorized_code_files_treats_multiline_decorator_dependency_authz_as_route_authz` covers multi-line route decorators; `test_map_authorized_code_files_treats_security_dependency_authz_as_route_authz` and `test_map_authorized_code_files_treats_decorator_security_authz_as_route_authz` cover same-line `Security(require_user)` forms; matching source-audit tests cover the hypothesis result. | Extend to aliased dependencies and scoped `Security(...)` forms in later Phase 3 slices. |
| Browser-level V0 E2E | Pending | Current Web test stack uses Node tests over helpers and source files; `apps/web/package.json` does not include Playwright. | Add Playwright or another browser runner as a separate setup task if full browser E2E is required. |

## Phase Status

| Phase | Current Status | Notes |
| --- | --- | --- |
| Phase 0: current-state and safety boundary freeze | Complete | The plan is documented and implementation uses existing FastAPI/Next/pipeline modules rather than a parallel architecture. |
| Phase 1: V0 local source audit MVP | Complete | CLI/API tests cover scope, intake, Semgrep, dependencies, hypotheses, and report output. |
| Phase 2: V0 quality gate and persistence | Complete for API and helper-level Web smoke | Pipeline run, artifact provenance, report preview, validation workspace, finding candidate gates, and Web helper sequencing are covered by tests. Browser-level E2E is still pending. |
| Phase 3: V0.5 semantic audit and refutation | In progress; refutation, ranking-quality, service-layer authz, and dependency-injected authz heuristic slices complete | Source hypotheses now carry `false_positive_checks`, `refutation_status`, `priority_score`, and `ranking_reasons`; API tests cover ranking `unverified` traceable candidates above parked/refuted candidates; Web run detail, report preview, and dashboard expose the state read-only; source mapping suppresses the narrow route-to-service, same-line and multi-line FastAPI handler `Depends(require_user)`/`Security(require_user)`, and same-line or multi-line route decorator `dependencies=[Depends(require_user)]`/`dependencies=[Security(require_user)]` authorization false positives. |
| Phase 4-7: V1/V2/V3/V4 | Plan/advisory only | Existing modules may model these areas, but they should remain Scope Guarded, redacted, non-executing, and human-approved. |

## Recommended Next Slice

1. Add a browser-level V0 E2E only if the project wants rendered-flow confidence beyond the existing Node helper smoke.
2. Continue Phase 3 with a deeper semantic-quality target:
   improve source-fact heuristics for aliased dependencies, scoped `Security(...)` forms, multi-hop service calls, ownership checks, and impact reasoning while keeping outputs advisory.
3. Keep all Phase 3 outputs advisory: no live validation, no automatic finding promotion, and no report submission without the existing manual gates.

## Current V0 Exit Criteria

V0 can be treated as API-complete when these commands pass:

- `python -m pytest` from `apps/api`
- `npm test` from `apps/web`
- `npm run lint` from `apps/web`
- `npm run build` from `apps/web`

V0 can be treated as helper-demo-ready after the Web smoke test passes. Full rendered-flow demo readiness still requires either a browser-level E2E or an explicitly documented decision to stay with helper-level smoke tests.

## Latest Verified Web Slice

The refutation visibility and ranking slice was verified with:

- `npm test` from `apps/web`
- `npm run lint` from `apps/web`
- `npm run build` from `apps/web`

These checks cover the Web helper smoke, source-audit refutation/ranking metadata typing, run detail display, report preview display, and dashboard refutation summary. The API test suite also covers source-audit hypothesis ranking and propagation into finding JSON and Markdown reports.
