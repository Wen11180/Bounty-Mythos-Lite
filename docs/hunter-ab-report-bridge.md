# A+B Candidate → Report Draft Bridge

Generated: 2026-07-13T01:38:03Z

Safety: submission blocked; no live validation; hunter candidates remain unverified.

- packages: 2
- total drafts: 1
- report_submission_allowed: `False`

## Packages

| package | retained | drafts | submission_blocked | multi_engine | residual_file | residual_gate | patch |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `my-local-ssrf-webhook-retain-lab` | 1 | 1 | `True` | `needs_human_review` | `True` | `ready_for_human_review` | `True` |
| `my-gh-plane-user-mass-lab` | 0 | 0 | `True` | `false_positive_likely` | `True` | `human_rejected_or_fp` | `True` |

## my-local-ssrf-webhook-retain-lab

Multi-engine verdicts (non-executing, not confirmed):

- `H-001`: `needs_human_review` (agreement=0.5455, confirmed=False)
- `H-002`: `needs_human_review` (agreement=0.8, confirmed=False)

Human residual gates (submission still blocked):

- `H-001`: `ready_for_human_review` (open=0, submit=False)

Intake profile (advisory stack detection; no network):
- status: intake_profile_ready
- languages: JavaScript, TypeScript
- frameworks: Express
- package_managers: npm
- entrypoints: 4
- auth_components: 1
- execution_allowed: False

Dependency / SBOM profile (local only; no live CVE lookup):
- status: dependency_profile_ready
- ecosystems: npm
- components: 1
- reachable: 1
- advisory_flagged: 0
- live_advisory_lookup: False
- execution_allowed: False

Residual runner (local static only; requires residual_review approval):
- aggregate_status: residual_run_completed_local_static
- completed_runs: 1
- candidate `H-001`: `residual_run_completed_local_static` planned=3 done=3 gaps=2 approved=True exec=False live=False

Local Semgrep runner (explicit human flag; package-root only; no remote rules):
- status: skipped_no_human_local_flag
- human_flag: False
- command_executed: False
- findings: 0
- binary_available: False
- remote_rules: False
- execution_allowed: False

Local CodeQL runner (explicit human flag; package-root only; no remote packs):
- status: skipped_no_human_local_flag
- human_flag: False
- command_executed: False
- findings: 0
- binary_available: False
- database_source: missing
- query_suite_source: missing
- remote_packs: False
- execution_allowed: False

Deeper multi-engine verifier (local static agreement only; never exploit verification):
- deep_stack_attached: True
- engine_count: 31
- engines: agent_memory, authorized_web_api, codebase_map, codeql_runner, continuous_scan, crash_codepath, crash_regression, crash_triage, crs_fuzzing, deep_code_reasoning, deep_research, finding_dedup_risk, human_gate_dry_run, human_residual_gate, human_review_approvals, hunter_loop, knowledge_base, local_fuzz_runner, local_fuzz_sandbox, long_horizon, multi_hour_agent_loop, patch_diff_learner, patch_validation, protocol_aware_fuzzing, report_bridge, residual_patch_decision_api, semgrep_advisory, semgrep_runner, variant_analysis, vuln_chain_builder, wall_clock_multi_hour_runner
- verdict H-001: status=needs_human_review agreement=0.5455 engines=31 confirmed=False
- verdict H-002: status=needs_human_review agreement=0.8 engines=31 confirmed=False

CRS/fuzz plan (plan-only; no auto execution):
- status: crs_fuzzing_plan_ready
- candidates: 1
- harnesses: 1
- harness_export_written: False
- harness_export_count: 0
- human_allow_harness_write: False
- scanned_files: 1
- fuzzer_status: not_executed
- execution_allowed: False
- promotion_allowed: False

Local fuzz sandbox (plan/export only; never auto-run):
- status: local_fuzz_sandbox_plan_ready
- targets: 1
- sandbox_export_written: False
- sandbox_export_count: 0
- human_allow_sandbox_write: False
- process_spawn_allowed: False
- execution_allowed: False
- crash_promotion_allowed: False

### Protocol-aware fuzzing (V4 plan-only)
- status: protocol_aware_fuzzing_plan_ready
- targets: 1
- grammar_plans: 1
- seed_plans: 4
- export_written: False
- process_spawn_allowed: False
- execution_allowed: False

### Patch Diff Learner (V4 plan-only)
- status: patch_diff_learner_plan_ready
- patterns: 3
- offline_diffs: 0
- bridge_diffs: 3
- export_written: False
- auto_pr_allowed: False
- patch_ready: False
- execution_allowed: False

### Variant Analysis (V4 plan-only)
- status: variant_analysis_plan_ready
- variants: 5
- seeds: 5
- offline_hints: 0
- export_written: False
- execution_allowed: False
- confirmed_vulnerability: False

### Vulnerability Chain Builder (V4 plan-only)
- status: vuln_chain_builder_plan_ready
- chains: 7
- seeds: 7
- offline_hints: 0
- export_written: False
- execution_allowed: False
- confirmed_vulnerability: False

### Deep Code Reasoning (V4 plan-only)
- status: deep_code_reasoning_plan_ready
- paths: 14
- permission_models: 1
- seeds: 14
- export_written: False
- execution_allowed: False
- confirmed_vulnerability: False

Local fuzz target plan (in-process execution disabled; never promote):
- status: skipped_no_human_local_fuzz_flag
- targets: 1
- runnable: 0
- executed: False
- crash_count: 0
- crash_export_written: False
- process_spawn_allowed: False
- crash_promotion_allowed: False
- execution_allowed: False

Crash triage (dedupe/minimize/root-cause advisory; never promote):
- status: crash_triage_no_crashes
- input_crashes: 0
- clusters: 0
- reproducible: 0
- minimized: 0
- executed: False
- export_written: False
- crash_promotion_allowed: False
- execution_allowed: False

Crash residual regression (plan-only tests from triaged clusters; never auto-run):
- status: crash_regression_no_clusters
- suggestions: 0
- reproducible_linked: 0
- minimized_linked: 0
- codepath_linked: 0
- export_written: False
### Crash code-path linking
- status: crash_codepath_no_clusters
- links: 0
- resolved: 0
- primary_paths: 0
- export_written: False
- package_code_execution_allowed: False
- crash_promotion_allowed: False
- confirmed_vulnerability: False

Authorized Web/API plan (package ingest; plan-only; never live validate/submit):
- status: authorized_web_api_plan_ready
- operations: 4
- role_diffs: 4
- business_logic: 8
- execution_allowed: False
- report_submission_allowed: False

Patch industrial loop (advisory sketches + planned regression only):
- status: patch_loop_completed_advisory
- items: 2
- advisory: 2
- regression_plans: 10
- code_context_hits: 6
- auto_pr_allowed: False
- patch_ready: False

External patch PR workflow (plan/export only; never auto-PR/git/gh):
- status: patch_pr_export_ready
- items: 2
- ready: 2
- exported: 0
- export_written: False
- auto_pr_allowed: False
- pr_opened: False
- patch_ready: False

Patch suggestions (advisory only; no auto-PR / no exploit PoC):

- `H-001`: `advisory_patch_suggestion` (auto_pr=False, exploit_poc=False, submit=False)
  - Introduce a shared URL validation helper (scheme allowlist, hostname denylist, private-IP block) used by all outbound fetch entry points.
  - Call the helper immediately before HTTP client requests for user-controlled URLs (e.g. subscriberUrl / webhook targets).
  - Reject redirects that re-target private/metadata hosts (or disable redirects when not required).

### H-001 — missing_ssrf_validation:deliver_local_lab_webhook

- route: `POST /local/lab/webhooks/deliver`
- status: `unverified_hypothesis`
- multi_engine_verdict: `needs_human_review`
- confirmed_vulnerability: `False`
- human_review_required: `True`
- submission_blocked: `True`
- title: Possible ssrf issue on POST /local/lab/webhooks/deliver (root=missing_ssrf_validation:deliver_local_lab_webhook). Unverified hunter candidate; local review only.
- next_allowed_action: Human review of the cited local evidence.
- safety_blockers: `execute_live_validation, touch_real_user_data, submit_report`

Validation plan steps:

- Local review only for POST /local/lab/webhooks/deliver: confirm whether an ownership or authorization guard runs before the sensitive sink reached via deliver_local_lab_webhook.
- Do not execute live validation, access production accounts, or submit a report.

Validation workspace (prep only):

- status: `awaiting_approval`
- allowed_to_execute: `False`
- human_approval_required: `True`
- non_destructive_only: `True`
- no_real_user_data: `True`

Refutation questions:

- Does an observed local authorization guard execute before the sensitive sink?
- Does observed local data flow prove the route is public or otherwise non-sensitive?

Human gate dry-run (offline e2e proof; never probes H1 / never auto-submits):
- status: human_gate_dry_run_ready
- checkpoints: 10
- pass/fail: 10/0
- chain_complete: True
- chain_safe: True
- export_written: False
- report_submission_allowed: False

  - `HG-01-package`: `pass` - Authorized package identity present
  - `HG-02-submission-blocked`: `pass` - Package-level submission remains blocked
  - `HG-03-residual-gate`: `pass` - Human residual gate present and non-submitting
  - `HG-04-report-draft-safety`: `pass` - Report drafts stay submission-blocked
  - `HG-05-multi-engine-not-confirmed`: `pass` - Multi-engine never confirms vulnerability
  - `HG-06-approvals-context-only`: `pass` - Human review approvals remain context-only
  - `HG-07-patch-pr-blocked`: `pass` - Patch / external PR stay non-auto
  - `HG-08-crash-stack-non-promote`: `pass` - Crash residual stack never promotes
  - `HG-09-global-safety-scrub`: `pass` - Top-level safety scrub
  - `HG-10-human-next-action`: `pass` - Next allowed action remains human-controlled

### Finding Dedup / Risk Prioritization
- status: finding_dedup_risk_plan_ready
- clusters: 2
- risk_queue: 2
- seeds: 2
- export_written: False
Agent memory (V3 advisory ranking only; never grants execute/submit):
- status: agent_memory_ready
- entries: 3
- fp_patterns: 0
- candidate_hints: 1
- export_written: False
- ranking_permission_granted: False
- report_submission_allowed: False

  - `retain-residual-H-001` [residual_disposition]: Residual disposition ready_for_human_review for H-001; still submission-blocked.
  - `mev-H-001` [retain_signal]: Multi-engine status needs_human_review for H-001; not confirmed vulnerability.
  - `pkg-my-local-ssrf-webhook-retain-lab` [retain_signal]: Memory scoped to authorized package my-local-ssrf-webhook-retain-lab.

Continuous scan (V3 cadence plan only; never auto-scans):
- status: continuous_scan_plan_ready
- jobs: 6
- watches: 7
- cadence: manual_or_approved_ci_only
- export_written: False
- auto_scan_allowed: False

  - `CS-01-scope-policy`: Re-check authorized scope and policy artifacts (my-local-ssrf-webhook-retain-lab) (human_local_static_reaudit)
  - `CS-02-static-surface`: Re-run intake + hunter static surface on authorized package (bridge_operator_trial_plan)
  - `CS-03-residual-gates`: Refresh residual checklist dispositions without live validation (human_residual_gate_refresh)
  - `CS-04-advisory-static`: Optional local Semgrep/CodeQL plan refresh (human flag only) (local_static_runner_plan)
  - `CS-05-memory-rank`: Refresh advisory agent-memory rank hints from new residuals (agent_memory_refresh_plan)
  - `CS-99-stop`: Stop before auto-scan / public targets / submit (safety_stop)

Patch validation (V3 non-destructive recheck plan; never live-validates):
- status: patch_validation_plan_ready
- items: 2
- ready: 2
- steps: 10
- export_written: False
- patch_ready: False
- live_validation_allowed: False

  - `pv-loop-H-001` cand=`H-001` status=`planned_ready_for_human_recheck`
  - `pv-loop-H-002` cand=`H-002` status=`planned_ready_for_human_recheck`

### Deep Research (V4 plan-only)
- status: deep_research_plan_ready
- chains: 1
- variants: 1
- unresolved_refutations: 1
- knowledge_updates: 2
- export_written: False
- execution_allowed: False

### Long Horizon (V4 plan-only)
- status: long_horizon_plan_ready
- paths: 9
- switches: 10
- iterations: 6
- reflections: 4
- export_written: False
- auto_path_switch_allowed: False
- execution_allowed: False

### Knowledge Base (section-7 patterns)
- status: knowledge_base_ready
- patterns: 15
- offline_artifacts: 0
- derived: 15
- export_written: False
- ranking_permission_granted: False
- execution_allowed: False

### Multi-Hour Agent Loop
- status: multi_hour_agent_loop_plan_ready
- phases: 6
- sessions: 6
- human_gates: 5
- handoffs: 6
- export_written: False
- auto_tick_allowed: False
- execution_allowed: False


### Wall-Clock Multi-Hour Runner
- status: wall_clock_multi_hour_runner_plan_ready
- slots: 6
- ticks: 16
- stop_conditions: 6
- export_written: False
- auto_tick_allowed: False
- execution_allowed: False


### Residual Patch Decision API
- status: residual_patch_decision_api_ready
- decisions: 2
- decided: 2
- residual: 1
- patch: 1
- export_written: False
- execution_allowed: False
- patch_ready: False

## my-gh-plane-user-mass-lab

Multi-engine verdicts (non-executing, not confirmed):

- `H-001`: `false_positive_likely` (agreement=1.0, confirmed=False)

Human residual gates (submission still blocked):

- `H-001`: `human_rejected_or_fp` (open=0, submit=False)

Intake profile (advisory stack detection; no network):
- status: intake_profile_ready
- languages: JavaScript, Python, TypeScript
- frameworks: Django, Express
- package_managers: npm
- entrypoints: 4
- auth_components: 1
- execution_allowed: False

Dependency / SBOM profile (local only; no live CVE lookup):
- status: dependency_profile_ready
- ecosystems: npm, pypi
- components: 10
- reachable: 10
- advisory_flagged: 0
- live_advisory_lookup: False
- execution_allowed: False

Residual runner (local static only; requires residual_review approval):
- aggregate_status: skipped_no_human_approval
- completed_runs: 0
- candidate `-`: `skipped_no_human_approval` planned=5 done=0 gaps=0 approved=False exec=False live=False

Local Semgrep runner (explicit human flag; package-root only; no remote rules):
- status: skipped_no_human_local_flag
- human_flag: False
- command_executed: False
- findings: 0
- binary_available: False
- remote_rules: False
- execution_allowed: False

Local CodeQL runner (explicit human flag; package-root only; no remote packs):
- status: skipped_no_human_local_flag
- human_flag: False
- command_executed: False
- findings: 0
- binary_available: False
- database_source: missing
- query_suite_source: missing
- remote_packs: False
- execution_allowed: False

Deeper multi-engine verifier (local static agreement only; never exploit verification):
- deep_stack_attached: True
- engine_count: 30
- engines: agent_memory, authorized_web_api, codebase_map, codeql_runner, continuous_scan, crash_codepath, crash_regression, crash_triage, crs_fuzzing, deep_code_reasoning, deep_research, finding_dedup_risk, human_gate_dry_run, human_residual_gate, human_review_approvals, hunter_loop, knowledge_base, local_fuzz_runner, local_fuzz_sandbox, long_horizon, multi_hour_agent_loop, patch_diff_learner, patch_validation, protocol_aware_fuzzing, report_bridge, residual_patch_decision_api, semgrep_runner, variant_analysis, vuln_chain_builder, wall_clock_multi_hour_runner
- verdict H-001: status=false_positive_likely agreement=1.0 engines=30 confirmed=False

CRS/fuzz plan (plan-only; no auto execution):
- status: crs_fuzzing_plan_ready
- candidates: 4
- harnesses: 4
- harness_export_written: False
- harness_export_count: 0
- human_allow_harness_write: False
- scanned_files: 4
- fuzzer_status: not_executed
- execution_allowed: False
- promotion_allowed: False

Local fuzz sandbox (plan/export only; never auto-run):
- status: local_fuzz_sandbox_plan_ready
- targets: 4
- sandbox_export_written: False
- sandbox_export_count: 0
- human_allow_sandbox_write: False
- process_spawn_allowed: False
- execution_allowed: False
- crash_promotion_allowed: False

### Protocol-aware fuzzing (V4 plan-only)
- status: protocol_aware_fuzzing_plan_ready
- targets: 4
- grammar_plans: 4
- seed_plans: 16
- export_written: False
- process_spawn_allowed: False
- execution_allowed: False

### Patch Diff Learner (V4 plan-only)
- status: patch_diff_learner_plan_ready
- patterns: 2
- offline_diffs: 0
- bridge_diffs: 2
- export_written: False
- auto_pr_allowed: False
- patch_ready: False
- execution_allowed: False

### Variant Analysis (V4 plan-only)
- status: variant_analysis_plan_ready
- variants: 3
- seeds: 3
- offline_hints: 0
- export_written: False
- execution_allowed: False
- confirmed_vulnerability: False

### Vulnerability Chain Builder (V4 plan-only)
- status: vuln_chain_builder_plan_ready
- chains: 4
- seeds: 4
- offline_hints: 0
- export_written: False
- execution_allowed: False
- confirmed_vulnerability: False

### Deep Code Reasoning (V4 plan-only)
- status: deep_code_reasoning_plan_ready
- paths: 8
- permission_models: 1
- seeds: 8
- export_written: False
- execution_allowed: False
- confirmed_vulnerability: False

Local fuzz target plan (in-process execution disabled; never promote):
- status: skipped_no_human_local_fuzz_flag
- targets: 4
- runnable: 0
- executed: False
- crash_count: 0
- crash_export_written: False
- process_spawn_allowed: False
- crash_promotion_allowed: False
- execution_allowed: False

Crash triage (dedupe/minimize/root-cause advisory; never promote):
- status: crash_triage_no_crashes
- input_crashes: 0
- clusters: 0
- reproducible: 0
- minimized: 0
- executed: False
- export_written: False
- crash_promotion_allowed: False
- execution_allowed: False

Crash residual regression (plan-only tests from triaged clusters; never auto-run):
- status: crash_regression_no_clusters
- suggestions: 0
- reproducible_linked: 0
- minimized_linked: 0
- codepath_linked: 0
- export_written: False
### Crash code-path linking
- status: crash_codepath_no_clusters
- links: 0
- resolved: 0
- primary_paths: 0
- export_written: False
- package_code_execution_allowed: False
- crash_promotion_allowed: False
- confirmed_vulnerability: False

Authorized Web/API plan (package ingest; plan-only; never live validate/submit):
- status: authorized_web_api_plan_ready
- operations: 4
- role_diffs: 0
- business_logic: 0
- execution_allowed: False
- report_submission_allowed: False

Patch industrial loop (advisory sketches + planned regression only):
- status: patch_loop_skipped_all_not_applicable
- items: 1
- advisory: 0
- regression_plans: 5
- code_context_hits: 0
- auto_pr_allowed: False
- patch_ready: False

External patch PR workflow (plan/export only; never auto-PR/git/gh):
- status: patch_pr_export_empty
- items: 0
- ready: 0
- exported: 0
- export_written: False
- auto_pr_allowed: False
- pr_opened: False
- patch_ready: False

Patch suggestions (advisory only; no auto-PR / no exploit PoC):

- `H-001`: `not_applicable_refuted_or_unverified` (auto_pr=False, exploit_poc=False, submit=False)
  - No product patch recommended from this static trial — control evidence currently opposes the candidate.
  - If human reopens, re-check the same root-cause layer rather than adding payload filters.

_No retained candidates; no report drafts._

## Pass rule reminder

- Drafts are not confirmed vulnerabilities.
- multi_engine_verdict is local static agreement only; not exploit verification.
- human_residual_gate never unlocks submission or live validation.
- human_gate_dry_run never unlocks submission or live validation.
- agent_memory is ranking/advisory only; never grants execute/submit/promote.
- continuous_scan is cadence/plan only; never auto-scans public targets.
- patch_validation is non-destructive recheck plan only; never live-validates or auto-PR.
- deep_research is V4 multi-stage/variant plan only; never exploits, execute, or submit.
- variant_analysis is V4 first-class sibling search plan only; never exploits, promote, or submit.
- vuln_chain_builder is V4 first-class multi-stage chain plan only; never exploits, promote, or submit.
- deep_code_reasoning is V4 first-class permission/cross-file plan only; never exploits, promote, or submit.
- finding_dedup_risk is plan-only clusters + risk queue; never promotes, ranks as permission, or submits.
- long_horizon is V4 path-switch/reflection plan only; never auto-switches, executes, or submits.
- knowledge_base is section-7 structured pattern catalog only; never grants ranking/execute/submit.
- multi_hour_agent_loop is multi-session budget/handoff plan only; never auto-ticks, executes, or submits.
- wall_clock_multi_hour_runner is wall-clock schedule/tick-ledger only; never auto-ticks, executes, or submits.
- residual_patch_decision_api is offline decision snapshot/export/import only; never unlocks execute/submit/patch_ready.
- Submission remains blocked.
- Teaching labs must not be treated as bounty submissions.
