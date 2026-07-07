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
| Scan persists as auditable pipeline run | Complete | Source audit API and repository tests assert pipeline run creation, artifact id, timeline, validation gate, and report preview; browser E2E submits the source-audit form and lands on a rendered run detail page. | None for V0. |
| Artifact provenance links scan, evidence bundle, and report claims | Complete | Source audit persistence tests assert artifact usage records for `pipeline_run`, `evidence_bundle`, and `report_claim`. | Add UI display checks if artifact detail becomes part of the V0 demo path. |
| Validation workspace is human gated | Complete | Tests assert `allowed_to_execute == false`, `human_approved == false`, claim tasks require review, and manual observations use report-safe evidence refs. | None for V0. |
| Finding candidate requires manual evidence and claim review | Complete | API test covers blocked promotion before manual observation and claim review, then successful candidate creation after both gates. Web helper smoke covers the same sequence without validation, approval, or submission calls; browser E2E verifies rendered report and validation pages keep submission and execution controls absent. | None for V0. |
| Report submission remains manual after candidate creation | Complete | API test asserts candidate promotion does not set auto submission; report draft keeps `auto_submit_allowed == false`. | No automatic submission endpoint should be added without a separate human-gated design. |
| Web source audit entrypoint is local and human gated | Complete | Web tests assert `/source-audit` posts only local repo/scope inputs and contains no validation, finding promotion, or submission actions. Browser E2E submits a mocked local source-audit scan and verifies the rendered run remains review-gated. | None for V0. |
| Web report preview records claim review manually | Complete | Web tests assert claim review form and API helper exist and avoid validation/submission actions; helper smoke sequences it after source audit and manual observation. Browser E2E verifies the rendered report page exposes the manual submission gate and no submit-report control. | None for V0. |
| Web validation workspace records safe manual observation | Complete | Web tests assert safe observation types, safety notes, no hardcoded unsafe observation path, and helper smoke sequences observation before claim review. Browser E2E verifies the rendered workspace shows the preflight gate and no execute/approve validation control. | None for V0. |
| Phase 3 refutation and ranking metadata is carried end-to-end | Complete for the current narrow slice | API tests assert `unverified`, `parked`, and `refuted` classification plus `false_positive_checks`, `priority_score`, and `ranking_reasons`; `test_source_hypotheses_rank_high_impact_sinks_before_lower_impact_sinks` covers impact-aware ranking reasons for destructive or privilege-sensitive sinks; Web tests assert run detail, report preview, and dashboard expose the state read-only. | Deeper semantic audit heuristics and browser-level confirmation remain outside this slice. |
| Service-layer authorization reduces false-positive hypotheses | Complete for the current narrow slice | `apps/api/tests/test_codebase_map.py` covers route-to-service authz mapping; `apps/api/tests/test_source_audit.py` covers `run_source_audit` not raising an authorization hypothesis when the called service performs ownership/role authorization before a sensitive sink. | Extend to aliasing and multi-hop service calls in later Phase 3 slices. |
| Multi-hop service ownership reduces false-positive hypotheses | Complete for the current narrow slice | `test_map_authorized_code_files_does_not_mark_gap_when_repository_layer_has_owner_filter` covers route-to-service-to-repository propagation where the repository applies an account boundary filter before the service reaches a sensitive sink; `test_map_authorized_code_files_follows_imported_service_alias_to_repository_owner_filter` covers imported service aliases on the route edge; `test_map_authorized_code_files_follows_local_method_alias_to_repository_owner_filter` and `test_map_authorized_code_files_follows_chained_local_alias_to_repository_owner_filter` cover local aliases to repository methods; `test_map_authorized_code_files_follows_same_class_field_alias_to_repository_owner_filter` covers same-class `self.loader = repository.load_for_user` aliases; `test_map_authorized_code_files_follows_chained_same_class_field_alias_to_repository_owner_filter` covers same-class `self.safe_loader = self.loader` aliases; matching source-audit tests cover the route-service-repository hypothesis result. | Extend to deeper or ambiguous call chains in later Phase 3 slices. |
| Dependency-injected route authorization reduces false-positive hypotheses | Complete for the current narrow slice | `test_map_authorized_code_files_treats_dependency_injected_authz_as_route_authz` covers same-line FastAPI `Depends(require_user)` in handler signatures; `test_map_authorized_code_files_treats_multiline_signature_dependency_authz_as_route_authz` covers multi-line handler signatures; `test_map_authorized_code_files_treats_decorator_dependency_authz_as_route_authz` covers same-line route decorator `dependencies=[Depends(require_user)]`; `test_map_authorized_code_files_treats_multiline_decorator_dependency_authz_as_route_authz` covers multi-line route decorators; `test_map_authorized_code_files_treats_security_dependency_authz_as_route_authz` and `test_map_authorized_code_files_treats_decorator_security_authz_as_route_authz` cover same-line `Security(require_user)` forms; `test_map_authorized_code_files_treats_multiline_scoped_security_as_route_authz` covers multi-line scoped `Security(...)` route dependencies; `test_map_authorized_code_files_treats_imported_authz_alias_as_route_authz` covers imported authz function aliases; `test_map_authorized_code_files_treats_dependency_alias_in_signature_as_route_authz` and `test_map_authorized_code_files_treats_dependency_alias_in_decorator_as_route_authz` cover same-file dependency aliases; `test_map_authorized_code_files_treats_dependency_wrapper_as_route_authz` covers a cross-file dependency wrapper whose signature delegates to `Depends(require_user)`; `test_map_authorized_code_files_treats_dependency_wrapper_chain_as_route_authz` covers a two-hop dependency wrapper chain; matching source-audit tests cover the hypothesis result. | Extend to longer/ambiguous dependency wrappers in later Phase 3 slices. |
| Same-handler ownership filters reduce false-positive hypotheses | Complete for the current narrow slice | `test_map_authorized_code_files_treats_owner_filter_as_authz_check` covers a route handler that constrains object access with `owner_id == user_id` before a sensitive sink and suppresses the same-handler authorization-gap candidate; `test_map_authorized_code_files_treats_tenant_filter_as_authz_check` covers a multi-line `tenant_id == current_user.tenant_id` predicate; `test_map_authorized_code_files_treats_filter_by_account_boundary_as_authz_check` covers `filter_by(..., account_id=current_user.account_id)`; `test_map_authorized_code_files_treats_double_underscore_account_boundary_as_authz_check` covers Django-style `account__id=current_user.account_id`; `test_map_authorized_code_files_treats_double_underscore_in_account_boundary_as_authz_check` covers Django-style `account_id__in=current_user.account_ids`; `test_map_authorized_code_files_treats_membership_boundary_as_authz_check` covers `.in_(current_user.tenant_ids)` membership predicates; matching source-audit tests cover owner, tenant, account-boundary, double-underscore account, double-underscore membership, and membership hypothesis results. | Extend to additional complex ORM variants and multi-hop service ownership predicates in later Phase 3 slices. |
| Browser-level V0 E2E | Complete for rendered smoke | `apps/web/e2e/v0-source-audit.spec.ts` uses Playwright to submit the source-audit form, land on run detail, open report preview, and open validation workspace with a mock source-audit API. | Full API+database browser E2E remains a later integration slice if needed. |

## Phase Status

| Phase | Current Status | Notes |
| --- | --- | --- |
| Phase 0: current-state and safety boundary freeze | Complete | The plan is documented and implementation uses existing FastAPI/Next/pipeline modules rather than a parallel architecture. |
| Phase 1: V0 local source audit MVP | Complete | CLI/API tests cover scope, intake, Semgrep, dependencies, hypotheses, and report output. |
| Phase 2: V0 quality gate and persistence | Complete for API, helper-level Web smoke, and rendered browser smoke | Pipeline run, artifact provenance, report preview, validation workspace, finding candidate gates, Web helper sequencing, and browser-rendered source-audit/report/workspace flow are covered by tests. Full API+database browser E2E remains outside this slice. |
| Phase 3: V0.5 semantic audit and refutation | In progress; refutation, ranking-quality, impact-aware ranking, service-layer authz, dependency-injected authz, and ownership-filter heuristic slices complete | Source hypotheses now carry `false_positive_checks`, `refutation_status`, `priority_score`, `ranking_reasons`, impact context, and sink-symbol summaries; API tests cover ranking `unverified` traceable candidates above parked/refuted candidates and privilege/destructive sinks above lower-impact data sinks; Web run detail, report preview, and dashboard expose the state read-only; source mapping suppresses the narrow route-to-service, route-service-repository ownership boundary including imported service aliases, local repository-method aliases, and same-class `self.<alias>` repository-method aliases including one-hop chained aliases, same-line and multi-line FastAPI handler `Depends(require_user)`/`Security(require_user)`, same-line or multi-line route decorator `dependencies=[Depends(require_user)]`/`dependencies=[Security(require_user)]`, multi-line scoped `Security(...)` route dependencies, imported authz function aliases, same-file dependency alias, bounded cross-file dependency-wrapper authorization false positives through the covered two-hop chain, and same-handler `owner_id == user_id`, `tenant_id == current_user.tenant_id`, `filter_by(..., account_id=current_user.account_id)`, Django-style `account__id=current_user.account_id`, Django-style `account_id__in=current_user.account_ids`, plus `.in_(current_user.tenant_ids)` authorization filters. |
| Phase 4-7: V1/V2/V3/V4 | Plan/advisory only | Existing modules may model these areas, but they should remain Scope Guarded, redacted, non-executing, and human-approved. |

## Recommended Next Slice

1. Continue Phase 3 with a deeper semantic-quality target:
   improve source-fact heuristics for deeper dependency-wrapper chains, deeper or ambiguous service call chains, additional complex ORM variants, and richer impact reasoning while keeping outputs advisory.
2. Add a full API+database browser E2E only if rendered smoke is no longer enough for release confidence.
3. Keep all Phase 3 outputs advisory: no live validation, no automatic finding promotion, and no report submission without the existing manual gates.

## Current V0 Exit Criteria

V0 can be treated as API-complete when these commands pass:

- `python -m pytest` from `apps/api`
- `npm test` from `apps/web`
- `npm run lint` from `apps/web`
- `npm run build` from `apps/web`
- `npm run e2e` from `apps/web`

V0 can be treated as rendered-demo-ready after the Web smoke and browser E2E tests pass. Full API+database rendered-flow confidence remains a separate integration task.

## Latest Verified Web Slice

The refutation visibility and ranking slice was verified with:

- `npm test` from `apps/web`
- `npm run lint` from `apps/web`
- `npm run build` from `apps/web`
- `npm run e2e` from `apps/web`

These checks cover the Web helper smoke, source-audit refutation/ranking metadata typing, run detail display, report preview display, validation workspace display, browser-rendered V0 source-audit flow, and dashboard refutation summary. The API test suite also covers source-audit hypothesis ranking and propagation into finding JSON and Markdown reports.
