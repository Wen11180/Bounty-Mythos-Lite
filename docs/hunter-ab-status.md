> **状态（2026-07-24）**：本文是 2026-07-13 前后的 A+B/工厂阶段性操作日志与百分比估计，**不作为现役产品能力声明**。
> 现役实现快照见 `docs/product/requirements-and-features.md` 与根 `README.md`；产品阶段目标见 `docs/product/north-star.md`。
> 文中 “this session / Distance ~xx% / Latest package intake” 仅保留历史上下文。
# Bounty Mythos-Lite — A+B / Factory Current Status

Updated: 2026-07-13T01:38:22Z

Progress toward the final research factory in `私人 AI 漏洞研究系统最终方案.md`.

## North star stage

A+B candidate hunter is **near-complete**. Beyond-A+B factory stages now include:

```text
authorized package (scope/policy/api/har/code [+ optional advisory + residual checklist])
-> Scope Guard
-> Intake Agent (language/framework/entrypoint profile)
-> Dependency Agent / SBOM (local manifests + reachability; no live CVE)
-> candidate hunter (refute/dedupe)
-> optional local Semgrep CLI (explicit human flag; offline rules only)
-> optional local CodeQL CLI (explicit human flag; pre-built local DB+suite; no remote packs)
-> CRS/fuzz planner (package ingest; plan-only harness/fuzzer; never auto-execute)
-> optional local fuzz sandbox recipes (human flag; plan/export only; never execute)
-> optional local fuzz runner (human flag; in-process Python only; never AFL spawn/promote)
-> optional crash triage + minimize (human flag; in-process only; never promote)
-> optional crash residual regression plan (plan-only tests from clusters; never auto-run)
-> optional crash code-path linking (static source read only; never execute/promote)
-> optional human-gate dry-run (offline e2e checkpoints; never H1 probe/submit)
-> optional agent memory (V3 offline FP/retain/knowledge ranking only; never grants execute/submit)
-> optional continuous scan (V3 cadence/watch/job plan only; never auto-scan)
-> optional patch validation (V3 non-destructive recheck plan only; never live-validate/auto-PR)
-> optional patch diff learner (V4 learned root-cause/fix/regression patterns only; never apply/PR)
-> optional first-class variant analysis (V4 sibling search plans only; never exploit/promote/submit)
-> optional first-class vuln chain builder (V4 multi-stage chain plans only; never exploit/promote/submit)
-> optional first-class deep code reasoning (V4 permission/cross-file path plans only; never exploit/promote/submit)
-> optional first-class finding dedup / risk prioritization (V3 cluster+queue plans only; never promote/submit)
-> optional deep research (V4 multi-stage/variant plan only; never exploit/execute/submit)
-> optional long-horizon (V4 path-switch/reflection plan only; never auto-switch/execute/submit)
-> optional knowledge-base (section-7 structured patterns only; never ranking/execute/submit)
-> optional multi-hour agent loop (multi-session budget/handoff plan only; never auto-tick/execute/submit)
-> optional wall-clock multi-hour runner (schedule/tick-ledger only; never auto-tick/execute/submit)
-> Authorized Web/API planner (package ingest; role-diff/business-logic plan-only)
-> multi-engine verdict (hunter + codebase_map [+ offline Semgrep/CodeQL])
-> submission-blocked report draft
-> human residual gate (package checklist auto-ingest)
-> advisory patch suggestion (root-cause fix + regression text; no auto-PR)
-> Patch Agent industrial loop (code context + regression plan; no auto-PR)
-> External patch PR workflow (plan/export only; human opens PR outside system)
-> durable residual/patch human review approvals (context only)
-> residual/patch decision API (HTTP thin wrap + offline snapshot/export/import; context only)
-> human-approved residual runner (local static probes; no live/network)
-> human review only
```

## Scoreboard

| Track | Status | Notes |
| --- | --- | --- |
| L0 Safety defaults | **Green** | no auto attack/submit; blockers forced |
| L1 Fixture decision quality | **Green** | operator trials pass |
| H1 source packages (3) | **Green** | GitLab/WP/Node all refute-correct |
| Local DVWA / Juice / new-api | **Green** | teaching retain + non-teaching refute |
| GitHub portfolio (23 OSS) | **Green** | authz + ssrf (cal+miniflux+freshrss) + path (listmonk+paperless) + mass (mealie+immich+plane) + injection |
| Non-authz reverse calibration | **Green** | 4 retain teaching ↔ 4 OSS refute pairs |
| Multi-engine verifier | **Wired green** | trial/report bridge attached |
| Advisory Semgrep/CodeQL | **Package-ingest green** | offline `inputs/advisory/*` optional |
| Local Semgrep CLI runner | **Package-ingest green** | human flag only; offline rules; no remote packs |
| Local CodeQL CLI runner | **Package-ingest green** | human flag only; local DB+suite; no remote packs |
| CRS/fuzz planner (V1) | **Package-ingest green** | plan-only multi-lang; never execute/promote |
| Local fuzz sandbox (V1) | **Package-ingest green** | plan/export recipes under human flag; never spawn/promote |
| Local fuzz runner (V1) | **Package-ingest green** | human-flagged in-process Python only; never AFL spawn/promote |
| Crash triage + minimize (V1) | **Package-ingest green** | human-flagged classify/dedupe/minimize/repro; advisory root-cause; never promote |
| Crash residual regression (V1) | **Package-ingest green** | plan-only regression suggestions from triaged clusters; never auto-run/promote |
| Crash code-path linking (V1) | **Package-ingest green** | static links from triaged clusters to file/function/symbol; never execute package code/promote |
| Protocol-aware fuzzing (V4) | **Package-ingest green** | plan/export grammar+seeds; T-003h/B-002j; MEV protocol_aware_fuzzing; never spawn/promote |
| Patch Diff Learner (V4) | **Package-ingest green** | plan/export learned patterns; T-008d/B-005d; MEV patch_diff_learner; never apply/PR/patch_ready |
| Variant Analysis (V4) | **Package-ingest green** | plan/export sibling-search; T-013b/B-010b; MEV variant_analysis; never exploit/promote/submit |
| Vulnerability Chain Builder (V4) | **Package-ingest green** | plan/export multi-stage chains; T-013c/B-010c; MEV vuln_chain_builder; never exploit/promote/submit |
| Human gate dry-run (offline) | **Package-ingest green** | offline HG-01..10 checkpoints; never probes H1/submits; T-009 / B-006; MEV engine human_gate_dry_run |
| Agent memory (V3) | **Package-ingest green** | offline FP/retain/knowledge + bridge-derived rank hints; never ranking_permission/execute/submit; T-010 / B-007; MEV engine agent_memory |
| Authorized Web/API planner | **Package-ingest green** | scope/api/roles/code package ingest; plan-only; never live/submit |
| Report draft bridge | **Green** | always submission_blocked |
| Residual checklist file auto-ingest | **Green** | `_extract/RESIDUAL_CHECKLIST.md` + `inputs/residual*` |
| Human residual gate | **Package-ingest green** | hold/ready/reject; never unlocks submit |
| Patch suggestion scaffold | **Scaffold green** | advisory only; no auto-PR / no exploit PoC |
| Patch industrial loop | **Package-ingest green** | sketches + regression plans; always auto_pr=false |
| Patch PR workflow (external) | **Package-ingest green** | plan/export only; T-008c; never auto-PR/git/gh |
| Durable residual/patch approvals | **Scaffold green** | offline+DB audit; never unlocks submit/PR |
| Residual/patch decision API | **Package-ingest green** | offline snapshot/export/import + HTTP wrap; never unlocks submit/PR; MEV residual_patch_decision_api; bridge rpda/* |
| Intake stack detection | **Package-ingest green** | language/framework/entrypoint; no network |
| Dependency Agent / SBOM | **Package-ingest green** | local manifests+imports; offline advisory only; no live CVE |
| Residual runner (approval-gated) | **Package-ingest green** | local static probes only; plan-only without residual approval |
| Long Horizon (V4) | **Package-ingest green** | path-switch/reflection plan only; never auto-switch/execute/submit; T-014 / B-011; MEV engine long_horizon |
| Knowledge Base (section-7) | **Package-ingest green** | structured pattern catalog only; never ranking/execute/submit/live-learn; T-015 / B-012; MEV engine knowledge_base |
| Multi-Hour Agent Loop | **Package-ingest green** | multi-session budget/handoff plan only; never auto-tick/execute/submit; T-016 / B-013; MEV engine multi_hour_agent_loop |
| Wall-Clock Multi-Hour Runner | **Package-ingest green** | wall-clock schedule + human-gated tick ledger only; never auto-tick/execute/submit; T-017 / B-014; MEV engine wall_clock_multi_hour_runner; mevenc=23 |
| Industrial scheduler DAG | **Advisory green** | T-001b/c + T-002b/c + T-003 CRS + T-003c sandbox + T-003d local fuzz run + T-003e crash triage + T-003f crash regression + T-003g crash codepath + T-004 Web/API + T-007b residual + T-008/T-008b/T-008c patch+PR-export + T-009 human-gate dry-run + T-010 agent memory + T-011 continuous scan + T-012 patch validation + T-013 deep research + T-014 long horizon + T-015 knowledge base + T-016 multi-hour agent loop + T-017 wall-clock multi-hour runner |
| Live residual depth (Gitea) | **Green** | unauth fail-closed + dual-unit matrix |
| Live H1 API re-acquisition | **Blocked** | still **401** |
| Full research factory | **Partial** | V0 + CRS + CodeQL/Semgrep + patch loop + Web/API + crash stack + HG dry-run + V3 agent memory/continuous scan/patch validation + V4 deep research + long-horizon + knowledge-base + multi-hour agent-loop plan + wall-clock tick-ledger runner industrialization green; still missing valid H1 when unblocked + live e2e human gates proven + live autonomous wall-clock execution (intentionally human-gated only) |

## Latest package intake (this session)

| Package | Family | Trial | Notes |
| --- | --- | --- | --- |
| my-gh-freshrss-ssrf | ssrf | 2/0 refuted | FreshRSS 1.29.1 serverIsPublic/checkUrl before httpGet |
| my-gh-plane-mass | mass_assignment | 1/0 refuted | Plane v1.3.1 UserSerializer allowlist; dual-lab mevenc 31/30; FDR green |

## Reverse calibration pairs

| Family | Retain lab | Refute OSS |
| --- | --- | --- |
| ssrf | my-local-ssrf-retain (+semgrep advisory) | my-gh-cal-ssrf (+codeql control advisory); **+my-gh-miniflux-ssrf** + **my-gh-freshrss-ssrf** diversity |
| path | my-local-path-retain | my-gh-listmonk-path; **+my-gh-paperless-path** diversity |
| mass | my-local-mass-retain | my-gh-mealie-mass; **+my-gh-immich-mass** + **my-gh-plane-mass** diversity |
| inject | my-local-inject-retain | my-gh-listmonk-inject; **+my-gh-mealie-inject** diversity |

## Factory smoke (this slice)

Docs: `docs/hunter-ab-report-bridge.md` / `.json` (live bridge output)

| package | retained | residual_gate | patch_suggestion | ploop | pitems | ppr | ppready | intake | deps | residual_runner | semgrep_runner | codeql_runner |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| my-local-ssrf-retain | 1 | ready_for_human_review | advisory (auto_pr=False) | patch_loop_completed_advisory | 2 | blocked_until_patch_review | 0 | True (TS/Express) | 1 | plan-only | plan-only | plan-only (`skipped_no_human_local_flag`) |
| my-gh-cal-ssrf | 0 | human_rejected_or_fp | not_applicable | patch_loop_skipped_all_not_applicable | 2 | empty | 0 | True (TS/Express) | 8 | plan-only | plan-only | plan-only (`skipped_no_human_local_flag`) |

Bridge console now includes `web=` / `wops=` / `wdiff=` (Authorized Web/API package ingest).

Unit tests this arc: `test_crs_fuzzing` + industrial **12 passed**; bridge smoke includes `crs=` / `ccand=`.



## Slice note — my-gh-mealie-inject (2026-07-13)

- Second **injection** GitHub static package (diversity beyond listmonk-inject).
- Upstream mealie-recipes/mealie **v3.20.1**: SearchFilter normalize + QueryFilterBuilder ORM binds before 
un_sql.
- Trial: **2/0 refuted**, decision_quality pass; dual-lab retain mevenc=25 / package mevenc=24; submission_blocked=True.
- Portfolio **20 → 21** my-gh-* packages.
- Docs: docs/hunter-ab-mealie-inject-trial.{json,md}, docs/hunter-ab-mealie-inject-github.md.
- H1 remains **blocked_401** — no thrash.

## Distance to north star

| Layer | Honest range |
| --- | --- |
| A+B candidate hunter | **~96–98%** |
| Final-scheme factory (V0→full) | **~92–97%** (V4 multi-hour + knowledge-base + long-horizon + deep research + V3 residual stack + offline human-gate dry-run + crash stack + CRS + Web/API + RPDA offline export/import; still missing valid H1 when unblocked + live e2e human gates proven + true wall-clock multi-hour execution) |

Still missing for full `最终方案`:

1. ~~Crash triage + minimization after local fuzz~~ **done (human-gated; never promote)**
2. ~~Residual regression-test suggestions from triaged clusters~~ **done (plan-only; never auto-run)**
3. ~~Optional: richer crash_regression suggestions consuming code-path links~~ **done (plan-only enrichment)**
4. Optional valid H1 token — do not thrash while 401
5. ~~Offline human-gate dry-run (HG-01..10)~~ **done (package-ingest; never H1 probe)**
6. ~~V3 continuous scan + patch validation + agent memory~~ **done (plan-only; never auto-scan/live-validate)**
7. ~~V4 deep research bridge industrialization~~ **done (plan-only multi-stage/variant; never execute/exploit)**
7b. ~~V4 long-horizon + knowledge-base bridge industrialization~~ **done (plan-only path-switch + section-7 catalog; never auto-switch/ranking/execute)**
7c. ~~Multi-hour agent loop plan industrialization~~ **done (multi-session budget/handoff plan; never auto-tick/execute)**
8. End-to-end human gates proven when H1 unblocked (live program path; not dry-run)
9. True long-horizon agent loop / live protocol fuzz / automatic path switching beyond V4 plan depth

## What next (priority)

1. End-to-end human gates when H1 unblocked (live program path; do not thrash while 401)
2. Keep reverse-cal green; **no H1 thrash** while `blocked_401`
3. Optional: true wall-clock multi-hour runner beyond plan (still never auto-execute; human-gated ticks only)
4. ~~Optional: scaffold deepening (residual/patch decision API, human_review_approvals)~~ **done (offline export/import + bridge/MEV)**
5. ~~Multi-hour agent loop plan industrialization~~ **done (T-016; dual-lab mhal ready; mevenc=22)**
6. ~~V4 knowledge-base / long-horizon / deep research / V3 residual stack~~ **done**

## Safety floor (unchanged)

- No automatic attack of public targets
- No auto report submission
- No real user data / raw secrets in packages or logs
- Model/scanner output is never confirmed vulnerability


## Slice note — CRS harness export (2026-07-12T18:00:59Z)

- Optional approved harness local file write: **GREEN** (write-only; human flag)
- CLI: `--allow-crs-harness-write` → `package/_export/crs_harness/`
- Console: `hexport=` / `hexpc=`
- Scheduler: **T-003b** / **B-002d**
- Safety: still plan-only; never executes fuzzers or promotes crashes
- Factory distance estimate after this slice: **~70–80%** full factory; A+B still **~96–98%**
- Next priority: deeper multi-engine verifier; no H1 thrash while 401


## Slice note — deeper multi-engine verifier (2026-07-12T18:06:59Z)

- Deeper multi-engine verifier: **GREEN** (CRS + residual + Web/API + residual-gate + local runners)
- Bridge second-pass: `attach_deeper_multi_engine_to_bridge_result` → `mevdeep=` / `mevenc=`
- Scheduler: **T-006b** / **B-003b** (`verifier_agent`)
- Still never sets execution/validation/submission/confirmed true
- Factory distance estimate after this slice: **~70–80%**; A+B still **~96–98%**
- Next priority: approved local fuzz **execution** under human gate (still never auto); end-to-end human gates when H1 unblocked; no H1 thrash while 401


## Slice note — crash triage + minimization (2026-07-12T18:34:34Z)

- Crash triage + minimize: **GREEN** (code + tests + bridge + docs)
- Default plan-only; human flag --allow-crash-triage / human_allow_crash_triage
- Console: ctr= / ctre= / ctrc= / ctrep=
- Scheduler: **T-003e** / **B-002g**; MEV engine crash_triage
- Export: package/_export/crash_triage/<stamp>/ (promotion always false)
- Safety: never promote/spawn external fuzzer/submit; root-cause advisory only
- Factory distance estimate after this slice: **~76–86%** full factory; A+B still **~96–98%**
- Next priority: residual regression-test depth from triaged clusters (plan-only); no H1 thrash while 401


## Slice note — crash residual regression (2026-07-12T18:44:09Z)

- Crash residual regression planner: **GREEN** (code + tests + bridge + docs)
- Default plan-only from crash_triage clusters; optional `--allow-crash-regression-export`
- Console: `creg=` / `cregn=` / `cregx=`
- Scheduler: **T-003f** / **B-002h**; MEV engine `crash_regression`
- Export: `package/_export/crash_regression/<stamp>/` (never auto-run tests)
- Safety: test_auto_execute/promotion/submit always false
- Factory distance estimate after this slice: **~78–88%** full factory; A+B still **~96–98%**
- Next priority: end-to-end human gates when H1 unblocked; optional code-path-aware regression polish; no H1 thrash while 401


## Slice note — crash code-path linking bridge attach (2026-07-12T18:58:47Z)

- Crash code-path linking: **GREEN** (module + tests + MEV + scheduler + bridge call-site fixed)
- Bridge smoke: cpath=crash_codepath_no_clusters cpathn=0 cpathr=0 cpathx=False; mevenc=14
- Packages: my-local-ssrf-retain + my-gh-cal-ssrf; submission_blocked remains True
- Safety: package_code_execution/promotion/submit always false; static source read only
- Scheduler: **T-003g** / **B-002i**; MEV engine crash_codepath
- Combined suite: 72 passed (codepath/regression/triage/fuzz/crs/scheduler/mev/bridge)
- Factory distance estimate after this slice: **~80–90%** full factory; A+B still **~96–98%**
- Next priority: end-to-end human gates when H1 unblocked; optional richer regression suggestions consuming code-path links; no H1 thrash while 401


## Slice note — codepath-aware crash regression (2026-07-12T19:02:07Z)

- Bridge order: **crash_codepath → crash_regression** so regression can consume static links
- Enrichment fields: `codepath_linked*`, console `cregc=`
- Extra plan step `*-03b` anchors assertions near advisory static path (text-only)
- Safety unchanged: test_auto_execute/promotion/submit/package_code_execution always false
- Suite: **74 passed** (prior 72 + 2 enrichment tests)
- Bridge smoke: `cpath=crash_codepath_no_clusters ... cregc=0 mevenc=14`; submission_blocked=True
- Factory distance: still **~80–90%** full factory; A+B **~96–98%**
- Next priority: end-to-end human gates when H1 unblocked; no H1 thrash while 401

## Slice note — human-gate dry-run (offline) (2026-07-12T19:11:21Z)

- Human-gate dry-run: **GREEN** (code + tests + bridge + scheduler + MEV + docs)
- Default offline checkpoints HG-01..10; optional export `--allow-human-gate-dry-run-export`
- Console: `hg=` / `hgpass=` / `hgfail=` / `hgok=` / `hgsafe=` / `hgx=`
- Scheduler: **T-009** / **B-006**; MEV engine `human_gate_dry_run`; smoke `mevenc=15`
- Safety: never probes H1, never auto-submits, never unlocks execute/promote
- Combined suite: **80 passed**
- Factory distance estimate after this slice: **~82–91%** full factory; A+B still **~96–98%**
- Next priority: live end-to-end human gates when H1 unblocked; no H1 thrash while 401


## Slice note - agent memory (V3) (2026-07-12T19:17:32Z)

- Agent memory: **GREEN** (module + tests + bridge + scheduler + MEV + docs)
- Offline package ingest + bridge-derived FP/retain/knowledge; candidate rank hints only
- Console: `amem=` / `amenn=` / `amemfp=` / `amemh=` / `amemx=`
- Scheduler: **T-010** / **B-007**; MEV engine `agent_memory`; smoke `mevenc=16`
- Safety: `ranking_permission_granted` always false; never execute/submit/promote
- Combined focused suite: **53 passed**
- Bridge smoke:
  - my-local-ssrf-retain: `amem=agent_memory_ready amenn=3 amemh=1 mevenc=16 hg=ready submission_blocked=True`
  - my-gh-cal-ssrf: `amem=agent_memory_ready amenn=3 amemfp=2 mevenc=16 hg=ready submission_blocked=True`
- Factory distance estimate after this slice: **~84?92%** full factory; A+B still **~96?98%**
- Next priority: live end-to-end human gates when H1 unblocked; optional V3 continuous scan / patch validation plan depth; no H1 thrash while 401

## Continuous Scan + Patch Validation (V3) — verified 2026-07-12T19:31:03Z

| Track | Status | Notes |
| --- | --- | --- |
| Continuous Scan | **Green** | plan-only cadence/jobs/watches; T-011 / B-008; `cscan/cscann/cscanw/cscanx`; MEV engine `continuous_scan`; smoke mevenc=18 |
| Patch Validation | **Green** | non-destructive recheck plan; T-012 / B-009; `pval/pvaln/pvalr/pvals/pvalx`; never `patch_ready` / live-validate / auto-PR |

Smoke (both labs): `cscan=continuous_scan_plan_ready`, local `pval=patch_validation_plan_ready`, gh-cal `pval=patch_validation_waiting_for_fix_artifacts`, `submission_blocked=True`, focused suite **47 passed**.

Docs: `docs/hunter-ab-continuous-scan.md`, `docs/hunter-ab-patch-validation.md`.

Next priority remains: live H1 e2e human gates when unblocked; do not thrash H1 while 401.


## Slice note — V4 deep research industrialization (2026-07-12T19:37:49Z)

- V4 Deep Research factory wire: **GREEN** (module + tests + bridge + MEV + scheduler + docs)
- Console: `dres=` / `dresc=` / `dresv=` / `dresu=` / `dresx=`
- Scheduler: **T-013** / **B-010**; MEV engine `deep_research`; dual-lab `mevenc=19`
- Export: `package/_export/deep_research/<stamp>/` via `--allow-deep-research-export` (never executes)
- Safety: execution/validation/submit/promote/ranking/network/live always false
- Focused suite: **57 passed**; source_audit deep-research subset still green
- Factory distance estimate after this slice: **~88–94%** full factory; A+B still **~96–98%**
- Next priority: end-to-end human gates when H1 unblocked; no H1 thrash while 401


## Slice note — V4 knowledge-base bridge attach fix (2026-07-12T19:56:51Z)

- Root cause: bridge imported ttach_knowledge_base_to_bridge_result and printed kbase* but never called attach after long_horizon
- Fix: call attach after long_horizon, then final MEV re-deepen (includes knowledge_base engine)
- Dual-lab smoke (verified):
  - my-local-ssrf-retain: kbase=knowledge_base_ready kbasep=15 kbasex=False mevenc=21 lhor=long_horizon_plan_ready dres=deep_research_plan_ready submission_blocked=True
  - my-gh-cal-ssrf: kbase=knowledge_base_ready kbasep=15 kbasex=False mevenc=21 lhor=long_horizon_plan_ready submission_blocked=True
- Safety: ranking/execute/submit/auto_learn_live_sources all false
- Focused residual suite: **77 passed**
- Factory distance after verified smoke: **~90–96%** full factory; A+B still **~96–98%**
- Next priority: end-to-end human gates when H1 unblocked; no H1 thrash while 401


## Slice note — multi-hour agent loop plan industrialization (2026-07-12T20:04:12Z)

- Module: `apps/api/app/multi_hour_agent_loop/` (plan-only multi-session budget/handoff/gates)
- Bridge attach after knowledge_base; console `mhal/mhalp/mhals/mhalg/mhalx`
- Scheduler **T-016** / **B-013**; MEV engine `multi_hour_agent_loop`
- Dual-lab smoke (verified):
  - my-local-ssrf-retain: `mhal=multi_hour_agent_loop_plan_ready mhalp=6 mhals=6 mhalg=5 mhalx=False kbase=knowledge_base_ready mevenc=22 submission_blocked=True`
  - my-gh-cal-ssrf: same mhal*/kbase/mevenc=22, submission_blocked=True
- Safety: auto_tick/execute/submit/ranking always false
- Focused residual suite: **87 passed**
- Factory distance after verified smoke: **~91–97%** full factory; A+B still **~96–98%**
- Next priority: end-to-end human gates when H1 unblocked; no H1 thrash while 401

## Slice note — human_review_approvals scaffold deepen (2026-07-12T20:18:49Z)

- human_review_approvals: **GREEN deepen** (bridge counters + MEV + scheduler + retain-lab fixture + docs)
- Package optional ingest: `inputs/human_review_approvals.json` (allowlisted in release fixtures)
- Bridge: `human_review_approvals_status/count/decided_count/residual_count/patch_count` + summary
- Console: `hreview` / `hreviewn` / `hreviewd` / `hreviewr` / `hreviewp`
- MEV engine: `human_review_approvals`; dual-lab smoke **mevenc=24**
- Scheduler: **T-018** / **B-015**
- Dual-lab smoke (verified):
  - my-local-ssrf-retain: `hreview=human_review_approvals_ready hreviewn=2 hreviewd=2 hreviewr=1 hreviewp=1 mevenc=24 submission_blocked=True patch_ready=False`
  - my-gh-cal-ssrf: `hreview=human_review_approvals_empty hreviewn=0 mevenc=24 submission_blocked=True`
- Safety: never unlocks execute/submit/promote/`patch_ready`/`auto_pr`; unsafe flags force MEV blocked
- Focused residual suite: **52 passed**
- Factory distance estimate after this slice: **~92–97%** full factory; A+B still **~96–98%**
- Next priority: end-to-end human gates when H1 unblocked; no H1 thrash while 401; optional residual_patch_decision_api offline export/import still human-gated


## Slice ? authorized GitHub static package expand (miniflux SSRF)

Updated: 2026-07-12T20:31:36Z

- Added `authorized_packages/my-gh-miniflux-ssrf` (miniflux/v2 **v2.3.2** feed-fetch SSRF static model)
- Upstream excerpts: `IsNonPublicIP`, `BlockPrivateNetworks` DialContext, fetcher dial Control, feed absolute-URL validator
- Operator trial: **2/0 refuted**, finals=0, decision_quality **pass**, evidence `code:code.ts:validateUrlForSSRF`
- Dual-lab bridge (retain + miniflux): `submission_blocked=True`; retain mevenc=25; miniflux mevenc=24; no unlock flags
- GitHub portfolio: **17 ? 18** OSS packages
- H1: still **blocked_401** (no thrash)
- Distance unchanged honesty band: A+B **~96?98%**; full factory **~92?97%**
- Next priority: end-to-end human gates when H1 unblocked; no H1 thrash while 401; optional further GH static intake / wall-clock remains human-gated by design


## Slice — authorized GitHub static package expand (paperless-ngx path)

Updated: 2026-07-12T20:38:48Z

- Added `authorized_packages/my-gh-paperless-path` (paperless-ngx/paperless-ngx **v2.9.0** document path static model)
- Upstream excerpts: pathvalidate.sanitize_filename in generate_filename, PurePath(...).name for original_name, source_path under ORIGINALS_DIR, consumer generate_unique_filename write path
- Operator trial: **2/0 refuted**, finals=0, decision_quality **pass**, evidence code:code.ts:sanitize_filename
- Dual-lab bridge (retain + paperless-path): submission_blocked=True; retain mevenc=25; paperless-path mevenc=24; no unlock flags
- GitHub portfolio: **18 → 19** OSS packages
- Path-family diversity: listmonk-path + paperless-path (2nd path package)
- H1: still **blocked_401** (no thrash)
- Distance unchanged honesty band: A+B **~96–98%**; full factory **~92–97%**
- Next priority: end-to-end human gates when H1 unblocked; no H1 thrash while 401; optional further GH static intake / wall-clock remains human-gated by design


## Slice — authorized GitHub static package expand (immich mass-assignment)

Updated: 2026-07-12T20:42:18Z

- Added `authorized_packages/my-gh-immich-mass` (immich-app/immich **v2.7.5** self-update mass-assignment static model)
- Upstream excerpts: `UserUpdateMeDto` field allowlist (no isAdmin), `updateMe` field pick, admin-only privilege DTOs residual
- Operator trial: **1/0 refuted**, finals=0, decision_quality **pass**, evidence `code:code.ts:forbid_privilege_fields`
- Dual-lab bridge (retain + immich-mass): `submission_blocked=True`; retain mevenc=25; immich-mass mevenc=24; no unlock flags
- GitHub portfolio: **19 → 20** OSS packages
- Mass-family diversity: mealie-mass + immich-mass (2nd mass package)
- H1: still **blocked_401** (no thrash)
- Distance unchanged honesty band: A+B **~96–98%**; full factory **~92–97%**
- Next priority: end-to-end human gates when H1 unblocked; no H1 thrash while 401; optional further GH static intake / wall-clock remains human-gated by design

## Latest factory slice

- **finding_dedup_risk** greened (2026-07-13T01:22:26Z)
- Doc: `docs/hunter-ab-finding-dedup-risk.md`
- Dual-lab mevenc: retain **31**, mealie-inject **30** (post-DCR was 30/29)
- Dual-lab FDR: both packages clusters=2 queue=2 seeds=2
- Distance (A+B): ~97?98%; full factory ~95?97% (still not 100% while H1/live e2e missing)
- H1: still `blocked_401` ? no thrash
- Next: e2e human gates when H1 unblocked; optional residual polish / portfolio expand

## Finding Dedup / Risk Prioritization (latest slice)

- **Status:** package-ingest green (plan/export only)
- **Module:** `apps/api/app/finding_dedup_risk`
- **Scheduler:** T-005 / T-006 (existing DAG; first-class bridge module now)
- **MEV:** ENGINE_FINDING_DEDUP_RISK (dual-lab mevenc **31 / 30**)
- **Console:** `fdr=` / `fdrn=` / `fdrq=` / `fdrs=` / `fdrx=`
- **Export:** `--allow-finding-dedup-risk-export`
- **Doc:** docs/hunter-ab-finding-dedup-risk.md
- H1 remains `blocked_401`; no live e2e claim; submission always blocked

## Slice note ? finding_dedup_risk (V3 first-class)

Updated: 2026-07-13T01:22:26Z

- First-class Finding Dedup + Risk Prioritization greened (plan-only clusters + risk queue)
- Module: `apps/api/app/finding_dedup_risk`; tests: `test_finding_dedup_risk.py` (9) + industrial scheduler green
- Bridge: DCR -> **FDR** -> deeper MEV; CLI `--allow-finding-dedup-risk-export`
- Dual-lab (live bridge smoke, GREEN):
  - my-local-ssrf-retain: mevenc=**31**, fdr clusters=2 queue=2 seeds=2
  - my-gh-mealie-inject: mevenc=**30**, fdr clusters=2 queue=2 seeds=2
- Scheduler: T-005 dedup_agent / T-006 risk_prioritizer (unchanged DAG)
- Safety floor forced false including ranking_permission_granted
- H1 still **blocked_401** ? no thrash; not claiming 100% factory
- Distance: A+B **~97?98%**; full factory **~95?97%**
- Next priority: e2e human gates when H1 unblocked; optional residual polish only

## Changelog slice — my-gh-freshrss-ssrf (2026-07-13T01:30:48Z)

- Portfolio **21 → 22** my-gh-* packages.
- New package: uthorized_packages/my-gh-freshrss-ssrf (FreshRSS/FreshRSS **1.29.1**, ssrf family, expected refute).
- Operator trial: **2/0 refuted**, decision_quality pass (docs/hunter-ab-freshrss-ssrf-trial.*).
- Dual-lab bridge: retain mevenc=31 / freshrss mevenc=30; FDR fdrn=2 both; submission_blocked.
- H1 remains **blocked_401** — do not re-probe.
- Next: e2e human gates when H1 unblocked; optional residual polish / portfolio expand.

## Changelog slice — my-gh-plane-mass (2026-07-13T01:38:22Z)

- Portfolio **22 → 23** my-gh-* packages.
- New package: uthorized_packages/my-gh-plane-mass (makeplane/plane **v1.3.1**, mass_assignment family, expected refute).
- Operator trial: **1/0 refuted**, decision_quality pass (docs/hunter-ab-plane-mass-trial.*).
- Dual-lab bridge: retain mevenc=31 / plane-mass mevenc=30; FDR fdrn=2/1; submission_blocked.
- H1 remains **blocked_401** — do not re-probe.
- Next: e2e human gates when H1 unblocked; optional residual polish / portfolio expand (path/inject 3rd).
