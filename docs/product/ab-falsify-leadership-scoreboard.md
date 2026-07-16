# A+B falsify leadership scoreboard

**Claim scope:** authorized policy / API / HAR / local-code Candidate Hunter falsification quality only.

**Not claimed:** live bounty program superiority, XBOW live-target ranking, remote auto-attack, or auto-submission.

Updated: 2026-07-16

## What "leading" means here

For A+B research (authorized artifacts + local code):

1. Every terminal decision carries an auditable **Falsification Card**.
2. Retained candidates must state `broken_invariant` and `why_still_alive`.
3. Refuted / suppressed candidates must kill with **evidence-backed** kill attempts and `why_dead`.
4. Incomplete evidence stays `needs_evidence` with explicit gaps — never silent Top-N padding.
5. Shared-root multi-route families keep **one** retained card and mark siblings `deduplicated` with cards.
6. Ranking prefers survived kill score, then evidence completeness, then priority.
7. Nested parent ownership guards (`child.parent.ownerId`) must refute with kill evidence.
8. Multi-engine advisory aggregation must agree with hunter retain/refute without enabling execution or submission.
9. Safety flags stay false; no raw secrets in outputs.

## Lab scenarios (gate corpus)

| Scenario | Expected |
| --- | --- |
| `retain_unguarded_session` | retained + survived falsify card |
| `refute_ownership_guard` | refuted + kill evidence |
| `suppress_public_filter` | suppressed + kill evidence |
| `needs_evidence_api_only` | needs_evidence card on evidence request |
| `dedupe_multi_root_shared_service` | 1 retained + 2 deduplicated cards, final Top-1 |
| `held_out_transfer_ownership` | held-out transfer family refuted + kill evidence |
| `rank_two_retained_by_priority` | two retained finals ordered by ranking weights |
| `refute_nested_parent_ownership` | nested `parent.ownerId` guard refuted + kill evidence |
| `refute_python_ownership_deny` | Python `return deny()` ownership guard refuted + kill evidence |
| `refute_python_tenant_boundary` | Python `tenant_id != user.tenant_id` multi-tenant guard refuted + kill evidence |
| `refute_python_inline_ownership` | Inline handler ownership guard before sink refuted + kill evidence |
| `refute_python_async_ownership` | FastAPI async `await verify` ownership guard refuted + kill evidence |
| `refute_python_multihop_ownership` | Nested attribute ownership (`folder.project.owner_id`) refuted + kill evidence |
| `refute_python_role_owner_and` | `role != admin and owner_id != user.id` BoolOp guard refuted + kill evidence |
| `refute_python_membership` | `user.id not in record.member_ids` membership guard refuted + kill evidence |
| `refute_python_bool_helper_guard` | `if not can_access(...): deny` + positive-eq helper refuted + kill evidence |
| `refute_python_workspace_boundary` | `workspace_id != user.workspace_id` boundary refuted + kill evidence |
| `refute_python_assert_ownership` | `assert owner_id == user.id` refuted + kill evidence |
| `refute_python_or_boundary` | `owner_id != user.id or team_id != user.team_id` Or guard refuted + kill evidence |
| `refute_python_gated_eq` | Gated sink `if owner_id == user.id: send_file` refuted + kill evidence |
| `refute_python_ownership_decorator` | `@require_ownership` decorator refuted + kill evidence |
| `refute_python_query_filter` | ORM `filter_by(owner_id=user.id)` refuted + kill evidence |
| `refute_python_depends_ownership` | FastAPI `Depends(get_owned_record)` refuted + kill evidence |
| `refute_ts_membership_includes` | TS `memberIds.includes(user.id)` membership refuted + kill evidence |
| `refute_python_cross_file_ownership` | Python ownership helper defined in another file refuted + kill evidence |
| `refute_python_cross_file_bool_helper` | Cross-file `if not can_access(...): deny` positive helper refuted + kill evidence |
| `refute_python_class_method_ownership` | Class-method ownership helper (`svc.verify`) refuted + kill evidence |
| `refute_ts_cross_file_ownership` | TS ownership helper in non-router module refuted + kill evidence |
| `refute_python_assign_ownership_helper` | `record = verify_access(...)` assignment-form helper refuted + kill evidence |
| `refute_python_service_layer_ownership` | route → service → authz multi-hop ownership refuted + kill evidence |
| `refute_python_g_current_user` | Flask `g.current_user.id` principal ownership refuted + kill evidence |
| `refute_python_or_admin_owner_allow` | `admin or owner` positive gate with sink refuted + kill evidence |
| `refute_python_team_boundary` | team_id boundary mismatch deny refuted + kill evidence |
| `refute_ts_middleware_ownership` | Express middleware `requireOwner` on route refuted + kill evidence |
| `refute_ts_service_layer_ownership` | TS route → service → authz multi-hop refuted + kill evidence |
| `refute_python_created_by_boundary` | `created_by_id != current_user.id` creator boundary refuted + kill evidence |
| `refute_python_with_context_ownership` | `with ownership_context(...): sink` context-manager helper refuted + kill evidence |
| `refute_ts_use_middleware_ownership` | Express `router.use(path, ensureOwner)` path middleware refuted + kill evidence |
| `refute_python_django_view_ownership` | Django function view + `request.user` ownership (no route decorator) refuted + kill evidence |
| `refute_ts_nestjs_guard_ownership` | NestJS `@UseGuards(OwnerGuard)` ownership guard refuted + kill evidence |
| `refute_python_author_id_boundary` | `author_id != current_user.id` creator/author boundary refuted + kill evidence |
| `refute_python_try_ensure_owner` | `try: ensure_owner(...)` ownership helper refuted + kill evidence |
| `refute_python_ternary_ownership` | `sink if owner else deny` ternary ownership gate refuted + kill evidence |
| `refute_python_response_403` | `Response(status=403)` ownership deny refuted + kill evidence |
| `refute_python_getattr_owner` | `getattr(record, "owner_id")` ownership compare refuted + kill evidence |
| `refute_python_request_state_user` | FastAPI `request.state.user.id` principal refuted + kill evidence |
| `refute_python_graphql_context` | GraphQL `info.context.user.id` principal refuted + kill evidence |
| `refute_ts_prisma_owner_filter` | Prisma `where: { ownerId: req.user.id }` filter refuted + kill evidence |
| `retain_python_guard_after_sink` | ownership check **after** sink retained (ineffective order) |
| `retain_python_login_only` | login/authn-only check retained (no object ownership) |
| `retain_ts_guard_after_sink` | TS ownership compare after `sendFile` retained (order-sensitive) |
| `refute_python_walrus_ownership` | walrus `(owner := record.owner_id) != user` refuted + kill evidence |
| `refute_python_match_ownership` | `match owner_eq: case True/False` refuted + kill evidence |
| `retain_python_status_only` | status-only deny retained (not object ownership) |
| `retain_python_wrong_field_compare` | `status_id != user.id` wrong-field guard retained |
| `retain_python_role_only` | admin/role-only gate retained (no object ownership) |
| `retain_ts_login_only` | TS authn-only (`!req.user`) retained |
| `retain_ts_role_only` | TS pure `req.user.role` check retained for object-ownership gap |
| `retain_python_hardcoded_owner` | `owner_id != 1` hardcoded principal retained |
| `retain_python_spoofable_header_principal` | `owner_id != X-User-Id` header principal retained |
| `retain_python_wrong_object_unrelated` | ownership of unrelated loaded object retained (resource-linked) |
| `retain_ts_hardcoded_owner` | TS `ownerId !== 1` retained |
| `retain_ts_status_only` | TS status-only deny retained |
| `retain_python_query_param_principal` | `owner_id != request.args user_id` spoofable principal retained |
| `refute_java_spring_ownership` | Spring/Java object ownership guard refuted + kill evidence |
| `refute_go_ownership` | Go object ownership guard refuted + kill evidence |
| `refute_rails_ownership` | Rails/Ruby object ownership guard refuted + kill evidence |
| `retain_java_role_only` | Java pure RBAC must not false-refute IDOR |
| `retain_go_role_only` | Go pure role check must not false-refute IDOR |
| `retain_rails_role_only` | Rails pure role check must not false-refute IDOR |
| `retain_java_status_only` | Java status-only check must not false-refute IDOR |
| `refute_java_service_layer_ownership` | Java service-layer ownership refute + kill evidence |
| `refute_go_middleware_ownership` | Go middleware ownership refute + kill evidence |
| `refute_rails_before_action_ownership` | Rails before_action ownership refute + kill evidence |
| `retain_java_guard_after_sink` | Java guard-after-sink must retain |
| `retain_go_status_only` | Go status-only must retain |
| `retain_rails_status_only` | Rails status-only must retain |
| `refute_csharp_ownership` | C# ASP.NET object ownership refute + kill evidence |
| `refute_php_ownership` | PHP Laravel-style object ownership refute + kill evidence |
| `retain_csharp_role_only` | C# pure RBAC must not false-refute IDOR |
| `retain_php_role_only` | PHP pure role check must not false-refute IDOR |
| `multi_engine_advisory_consistent` | retain → `local_static_consistent`; refute+control → `false_positive_likely`; safety flags false |

## Leadership metrics (must all be 1.0)

| Metric | Meaning |
| --- | --- |
| `scenario_pass_rate` | Disposition + card semantics match expected |
| `safety_rate` | No high-risk secret markers in round JSON |
| `falsify_coverage` | Every scenario emits a falsification card |
| `card_valid_rate` | Cards pass schema/invariant validation |
| `retain_hit` | Expected retain scenarios retain |
| `refute_kill` | Expected refute scenarios kill with evidence |
| `suppress_kill` | Expected suppress scenarios kill with evidence |
| `needs_evidence_card_rate` | Incomplete evidence carries a needs_evidence card |
| `dedupe_kill` | Multi-root shared service keeps one retain and carded dedupes |
| `rank_order_hit` | Final retained order follows ranking weights |
| `nested_refute_kill` | Nested parent ownership scenarios kill with evidence |
| `multi_engine_agree` | Multi-engine advisory agrees with retain/refute dispositions |
| `python_refute_kill` | Python deny-return ownership helpers refute with evidence |
| `tenant_refute_kill` | Multi-tenant boundary helpers refute with evidence |
| `inline_refute_kill` | Inline handler ownership guards refute with evidence |
| `async_refute_kill` | Async Python ownership helpers refute with evidence |
| `multihop_refute_kill` | Multi-hop attribute ownership guards refute with evidence |
| `role_owner_and_refute_kill` | Role+owner BoolOp `And` guards refute with evidence |
| `membership_refute_kill` | Membership `NotIn` collection guards refute with evidence |
| `bool_helper_refute_kill` | Positive ownership helper + `if not helper(): deny` refute with evidence |
| `workspace_refute_kill` | Workspace boundary guards refute with evidence |
| `assert_refute_kill` | Assert ownership equality guards refute with evidence |
| `or_refute_kill` | BoolOp `Or` ownership boundaries refute with evidence |
| `gated_eq_refute_kill` | Positive-equality gated sinks refute with evidence |
| `decorator_refute_kill` | Ownership decorators refute with evidence |
| `query_filter_refute_kill` | ORM owner/tenant query filters refute with evidence |
| `depends_refute_kill` | FastAPI Depends ownership helpers refute with evidence |
| `ts_membership_refute_kill` | TypeScript membership `.includes` guards refute with evidence |
| `cross_file_py_refute_kill` | Cross-file Python ownership helper refute with evidence |
| `cross_file_bool_refute_kill` | Cross-file positive bool ownership helper refute with evidence |
| `class_method_refute_kill` | Python class-method ownership helper refute with evidence |
| `ts_cross_file_refute_kill` | Cross-file TypeScript ownership helper refute with evidence |
| `assign_helper_refute_kill` | Assignment-form ownership helper refute with evidence |
| `service_layer_refute_kill` | Python multi-hop service-layer ownership refute with evidence |
| `g_current_user_refute_kill` | Flask `g.current_user` principal ownership refute with evidence |
| `or_admin_owner_refute_kill` | Positive `admin or owner` gated sink refute with evidence |
| `ts_middleware_refute_kill` | Express ownership middleware refute with evidence |
| `team_refute_kill` | team_id boundary refute with evidence |
| `ts_service_layer_refute_kill` | TS multi-hop service-layer ownership refute with evidence |
| `created_by_refute_kill` | creator `created_by_id` boundary refute with evidence |
| `with_context_refute_kill` | Python `with ownership_context` helper refute with evidence |
| `ts_use_middleware_refute_kill` | Express path-scoped `router.use` middleware refute with evidence |
| `django_view_refute_kill` | Django function-view ownership (candidate path fallback) refute with evidence |
| `ts_nestjs_guard_refute_kill` | NestJS `@UseGuards(OwnerGuard)` refute with evidence |

## Gate commands

```powershell
cd apps/api
python -m pytest tests/test_falsification_engine.py tests/test_ab_falsify_audit.py tests/test_ab_leadership_gate.py tests/test_candidate_hunter_hard_cases.py tests/test_human_hour_scorecard.py -q
python -m app ab-leadership-gate --out tmp/ab-leadership.json
python -m app human-hour-scorecard --out tmp/human-hour.json
python -m app human-hour-calibration --out tmp/human-hour-calibration.json
python -m app lab-leadership-rollup --out tmp/lab-leadership.json
```

## Studio operator projection

When Candidate Hunter stages are ready for a run, Studio candidate cards prefer hunter `final_candidates` and surface:

- `broken_invariant`
- `why_still_alive`
- falsification open dimensions / summary
- refutation questions

This is operator UX only. It does not enable execution, promotion, or report submission.

## Relationship to black-box leadership and human-hour proxies

- Black-box lab leadership: dual-role HAR / local-lab differential families (`black-box-lab-leadership-scoreboard.md`).
- A+B falsify leadership: cross-source hypothesis kill/survive cards on authorized code/API packages.
- Human-hour quality scorecard: simulated authorized-lab density proxies from the A+B hard corpus (`human-hour-quality-scoreboard.md`).
- Full product TOP1 still requires authorized live-program human-hour quality comparisons — not claimed by lab gates.

## Next toward real TOP1

1. Expand held-out families further (workspace variants, role/policy hybrids) without weakening safety gates. **Shipped:** Python deny-return, tenant, inline, async, multi-hop, `created_by_id`, `with` context managers, Django function views, Express `router.use` path middleware, NestJS `@UseGuards`, invalid-guard retains (status/wrong-field/role/TS login+role) in lab gate (65 scenarios).
2. Calibrate human-hour proxies against real authorized program review time (still no live superiority claim until measured). Synthetic fixture now mirrors more A+B packages.
3. Keep Studio projection audit-aligned as loop fields evolve.
4. Do **not** claim XBOW or live-program TOP1 from lab metrics alone.
