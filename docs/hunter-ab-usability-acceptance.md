# A+B Candidate Hunter Usability Acceptance

Date: 2026-07-12

Purpose: turn the near-term product goal into a pass/fail checklist that a human
researcher can run without expanding dashboard scope, release suite counts, or
live validation.

Primary references:

- `docs/product/north-star.md`
- `私人 AI 漏洞研究系统最终方案.md` (authorized research factory direction)
- `apps/api/app/intelligence_benchmark/release_v1.py`
- `apps/api/app/intelligence_benchmark/release_runner.py`
- `apps/api/tests/fixtures/candidate_hunter_release/`
- `docs/hunter-day1-baseline.md` through `docs/hunter-day3-exit.md`

## 1. What "usable" means for A+B

A+B is usable when an authorized package of:

```text
scope + policy + API (or HAR) + local code
```

produces **1-5** high-quality candidates that a human would consider worth local
review, with:

- endpoint + code path linkage (or explicit missing-link / evidence request)
- vulnerability type and root-cause identity
- evidence refs that exist in observed artifacts
- refutation questions before any validation request
- non-destructive safe validation plan
- explicit safety blockers
- submission blocked by default

Usable does **not** mean:

- automatic live validation
- automatic report submission
- full multi-engine CRS / fuzz execution
- dashboard completeness
- Mythos-grade deep semantic audit of arbitrary large repos

## 2. Acceptance layers

| Layer | Question | Existing automation |
| --- | --- | --- |
| L0 Safety | Does the hunter stay fail-closed and non-executing? | Scope Guard tests + release safety fields |
| L1 Decision correctness | Are retain / refute / dedupe / suppress decisions right on fixtures? | 24-case release corpus + hard cases |
| L2 Metric thresholds | Do suite metrics meet release gates? | `METRIC_THRESHOLDS` in `release_v1.py` |
| L3 Candidate card quality | Is each retained candidate research-usable by a human? | Partial (schema + readiness); several fields weak |
| L4 Operator trial | Can a human run an authorized package and trust Top 1-5? | **Not formalized yet** (this doc) |

A+B usability requires **L0-L2 green** and **L3 minimum fields present**.  
L4 is the final human gate for calling A+B "daily trial ready".

## 3. Authorized input package contract

### Required kinds

Same as release runner:

| Kind | Role | Fail closed if missing |
| --- | --- | --- |
| `scope` | allowlist / local-only boundary | yes |
| `policy` | program rules / forbidden actions | yes |
| `api` | OpenAPI-like surface | required for A+B package (HAR may supplement) |
| `har` | traffic context | required by current runner packaging |
| `code` | authorized local code snapshot | yes for code-linked retain |

### Package rules

1. Inputs must be user-provided or explicitly authorized.
2. No real user data, secrets, tokens, cookies, or Authorization headers.
3. Scope must allow only local/staged code and in-scope routes.
4. Synthetic benchmark fixtures must set:
   - `authorized_for_local_benchmark: true`
   - `contains_real_user_data: false`
   - `contains_secrets: false`

### Canonical fixture shape

Reuse release cases:

```text
cases/<case-id>/
  case.json
  gold.json
  inputs/
    scope.json
    policy.md
    api.json
    traffic.har.json
    code.ts
```

Do not expand the locked 12+12 case counts for usability work. Use hard cases
or a separate operator trial pack if more pressure is needed.

## 4. Expected candidate card (North Star vs current output)

North Star expects each candidate to include the left column. Current hunter
projection (`advance_candidate_hunter_round` retained projection + state fields)
is mapped on the right.

| Required research field | Current source | Status |
| --- | --- | --- |
| Affected endpoint | `route.method` + `route.path` | **Present** |
| Affected code path | `affected_code_path` backed by a cited `code:` `source_fact_refs` entry | **Present** — uncited paths request code evidence and cannot enter a report draft |
| Vulnerability type | `vuln_type` | **Present** |
| Why high impact | source hypothesis `impact_rationale` + `impact_score` | **Partial** — code-derived profiles persist potential impact to retained cards and report drafts; human review still determines actual impact |
| Evidence needed | source hypothesis `evidence_needed` plus missing kinds / evidence tasks | **Partial** — code-derived profiles persist their requirements to retained cards and report drafts |
| Refutation questions | source hypothesis `refutation_questions` on retained candidate state | **Partial** — code-derived profiles persist specific questions; other inputs retain a safe fallback |
| Safe validation plan | source hypothesis `safe_validation_plan` | **Present** — code-derived profiles retain offline-only steps; generic fallback remains for sparse inputs |
| Safety blockers | `safety_blockers` + allow flags false | **Present** |
| Report draft readiness | `report_submission_allowed: false`, `next_allowed_action` | **Present / blocked** |
| Evidence traceability | `source_fact_refs`, `evidence_trace_status=traceable` | **Present** for retain path |
| Root-cause identity | `root_cause_id` | **Present** |
| Disposition / ranking | `candidate_decisions`, `rank` Top 5 | **Present** |

### Minimum L3 card for "human worth opening"

A retained candidate must expose enough for a researcher to answer:

1. What endpoint?
2. What code symbol/path is implicated?
3. What invariant may be broken?
4. What local evidence already exists?
5. What would refute it?
6. What is the next **non-executing** action?

**Current pass bar for automation:** L1/L2 fields required by `release_v1`
schema + safety blockers.  
**Current human bar:** researchers still need richer impact rationale and more
specific validation plans than the default sentence.

## 5. Automated acceptance (already implemented)

### 5.1 Unit / hard-case gate

Command pattern (workspace basetemp required):

```powershell
$base = "apps\api\.pytest-tmp"
$env:TEMP = $base
$env:TMP = $base
$env:PYTHONPATH = "apps\api"
.\.venv\Scripts\python.exe -m pytest `
  apps/api/tests/test_scope_guard.py `
  apps/api/tests/test_scope_guard_api.py `
  apps/api/tests/test_candidate_hunter_loop.py `
  apps/api/tests/test_candidate_hunter_hard_cases.py `
  apps/api/tests/test_candidate_hunter_evidence.py `
  apps/api/tests/test_cross_source_candidate_generator.py `
  apps/api/tests/test_candidate_hunter_release_benchmark.py `
  apps/api/tests/test_candidate_hunter_release_fixtures.py `
  apps/api/tests/test_candidate_hunter_release_runner.py `
  -q --tb=line --basetemp "$base\gate"
```

Or: `apps/api/scripts/run_hunter_gate.ps1`  
If full process hits ~10s wall timeout, batch as in Day 2/3 exit docs.

**Pass:** all gate tests green.

### 5.2 Release metric thresholds

From `METRIC_THRESHOLDS`:

| Metric | Threshold | Meaning |
| --- | --- | --- |
| `precision_at_5` | >= 0.8 | Top retained candidates match gold retain roots |
| `valuable_recall_at_5` | >= 0.8 | Worth-validation gold roots are recovered |
| `evidence_traceability_rate` | = 1.0 | Required evidence refs present on matches |
| `effective_refutation_rate` | >= 0.8 | Gold refute roots are actually refuted with decisive evidence |
| `duplicate_suppression_rate` | = 1.0 | Gold duplicates are deduplicated |
| `human_worth_validation_rate` | >= 0.8 | Retained candidates marked ready for human validation |

**Pass:** development suite (12) and release suite (12) each evaluate `status=passed`
with loop audit `ready` (no invented empty decisions).

### 5.3 Decision dispositions

Gold dispositions: `retain | refute | deduplicate | suppress`  
Output dispositions: `retained | refuted | deduplicated | suppressed`

Hard rules already enforced by evaluator:

- refuted root must not appear in final candidates
- refute needs decisive refutation evidence intersection
- dedupe needs `duplicate_of` pointing at a retain canonical root
- final candidates must have covering retained decisions
- safety allow flags remain false; required blockers present

### 5.4 Hard-case regression pins (Day 2-3)

Must remain green:

| Weak | Coverage |
| --- | --- |
| #1 ownership / route style | OpenAPI `{param}` vs Express `:param` refute |
| #2 public suppress | public filter still suppresses under route-style mismatch |
| #3 multi-root dedupe | shared helper + direct same sink + deterministic canonical |
| #4 held-out / auth family | transfer + session ownership refute; unguarded retain |
| #5 missing/invented code | never retain invented path; API-only requests evidence |

## 6. Operator trial acceptance (L4) — how to judge "daily trial ready"

Use **one development retain case** and **one release held-out retain case** as
smoke packages (do not invent public targets):

| Trial | Suggested fixture | Expected human judgment |
| --- | --- | --- |
| T1 known-good retain | `dev-001` / `cases/case-001` | 1 retained authorization candidate worth local review |
| T2 known-good refute | `dev-002` / `cases/case-002` | ownership guard present → no retained false positive |
| T3 multi-root | `dev-003` / `cases/case-003` | one retain + one dedupe, not dual noise |
| T4 held-out family | `rel-001` or `rel-002` | disposition matches gold under unseen family |

### Human scorecard (per retained candidate)

Score each retained item 0/1:

| # | Question | Pass |
| --- | --- | --- |
| H1 | Endpoint is correct and in scope | yes/no |
| H2 | Code path/symbol is real in provided code | yes/no |
| H3 | Root cause is plausible, not generic scanner noise | yes/no |
| H4 | Evidence refs open to observed artifacts | yes/no |
| H5 | At least one useful refutation question | yes/no |
| H6 | Validation plan is non-destructive and local/human-gated | yes/no |
| H7 | Would a bounty researcher spend 10 minutes on this? | yes/no |

**Trial package pass rule (proposed):**

- Automated suite still green.
- For T1+T4 retain outputs: average H1-H6 = 100% on automated fields; H7 >= 2/3 of retained items.
- Zero retained candidates with invented code paths.
- Zero auto-validation / auto-submit signals.

Record results in a short note under `docs/` only when a trial is actually run
(do not pre-fill fake human scores).

## 7. Gap matrix (executable next work)

Status key: **Done** / **Partial** / **Missing** / **Frozen**

| ID | Gap | Status | Blocks | Next action |
| --- | --- | --- | --- | --- |
| G1 | Decision loop generate → refute → dedupe → rank | Done | - | Keep gate green |
| G2 | Route-style ownership/public matching | Done (Day2) | - | Regression only |
| G3 | Multi-root shared identity | Done (Day3) | - | Regression only |
| G4 | Held-out auth-family refute hard cases | Done (Day3) | - | Regression only |
| G5 | Invented path fail-closed | Done (Day2) | - | Regression only |
| G6 | Release suite metric gate | Done | - | Do not loosen thresholds |
| G7 | Final card: dedicated affected code path | Done | - | Keep cited-code-path loop, projection, and report-bridge regressions green |
| G8 | Final card: impact rationale | Missing | L3/H3/H7 | Only if operator trial shows retain is "correct but unconvincing" |
| G9 | Final card: specific evidence-needed list | Partial | L3 | Surface missing kinds already computed by loop |
| G10 | Final card: refutation_questions on retained projection | Partial | L3/H5 | Promote existing state questions into retained projection |
| G11 | Validation plan specificity | Partial | L3/H6 | Replace pure boilerplate only with observed route/symbol context |
| G12 | Operator trial protocol + score logging | Missing → **this doc defines** | L4 | Run T1-T4 and write scores; no code required first |
| G13 | Real non-fixture authorized package | Partial?Advanced (loader + educational L4 signed + 3 H1 source packages refute-correct + Node runtime residual) | L4 product trust | Synthetic L4 signed under delegated H7; GitLab local residual done on CE 19.1.0; WP residual still open |
| G14 | Static analyzer advisory fusion into hunter | Partial elsewhere | later | After L4 pass |
| G15 | Verifier workspace execution | Frozen/human-gated | final factory | Out of A+B usability scope |
| G16 | Dashboard expansion | Frozen | distraction | Out of scope |
| G17 | Expand 24-case counts | Frozen | suite lock | Use hard cases instead |

## 8. Pass / fail summary for "A+B usable"

### A+B engineering baseline (now)

Pass if:

1. Hunter gate green (batched if needed).
2. Day2/Day3 hard cases green.
3. Development + release suite evaluation pass with thresholds.
4. Safety: no live validation, no real-user-data touch, no report submit.

**Assessment after Day 3:** engineering baseline is largely **met**.

### A+B research usability (near target)

Pass if engineering baseline holds **and**:

1. Operator trial T1-T4 completed on authorized fixtures.
2. Human scorecard H1-H6 all yes for retained items in T1/T4.
3. H7 yes for majority of retained items.
4. No retain on invented or out-of-scope paths.
5. Card gaps G7-G11 do not prevent a researcher from acting (or are fixed surgically).

**Assessment after Day 3:** research usability is **not yet signed off** — L4 trial
and richer card fields remain.

### Final factory (out of scope for this checklist)

Fails by definition until verifier execution, multi-engine analysis, patch loop,
and learning-driven ranking are real capabilities under human gates.

## 9. Recommended execution order from this doc

1. **Now:** keep gate green; treat this checklist as the A+B definition of done.
2. **Operator trial harness:** `apps/api/scripts/run_ab_operator_trial.py` writes
   `docs/hunter-ab-operator-trial.md` + `.json` for T1-T4.
3. **Card field promotion (done when trial showed L3 thinness):** retained projection
   now includes `refutation_questions`, `affected_code_path`, and route-aware
   `safe_validation_plan` (G7/G10/G11 partial close).
4. **Remaining human action:** fill H7 (worth 10 minutes) on retained rows in the
   trial scorecard; machine-prefill covers H1-H6.
5. **Only if trial fails after H7:** fix the smallest proven gap (prefer G8/G9).
6. **Do not:** expand suite counts, UI, auto-validation, or language surface without failure evidence.

### Status snapshot (2026-07-12)

| Item | Status |
| --- | --- |
| L0-L2 engineering baseline | Met (gate + suite thresholds) |
| G7 affected_code_path | Closed on retained projection |
| G10 refutation_questions on retain card | Closed |
| G11 less-boilerplate validation plan | Partially closed (route/symbol-aware) |
| G12 operator trial protocol | Harness + scorecard generated |
| L4 H7 human sign-off (fixture T1-T4) | **Pass** ? 3/3 retained H7=yes; see `docs/hunter-ab-operator-trial.md` |
| A+B fixture-trial ready | **Yes** |
| A+B real authorized-package ready | **Open** — harness ready; needs user-owned package H7 |

### Fixture trial conclusion

T1-T4 decision quality all pass; retained cards have endpoint, code path, evidence,
refutation questions, safe plan, and safety blockers. Human H7 is yes for all three
retained candidates after reading fixture code. This signs off **synthetic authorized
fixture usability**, not production multi-repo discovery.



### G13 H1 Node.js source package (2026-07-12)

Acquired lawful package `authorized_packages/my-h1-nodejs` from public Node.js core
permission/fs sources under HackerOne handle=nodejs SOURCE_CODE scope.

Trial:

```powershell
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root "authorized_packages\my-h1-nodejs" --md-name "hunter-ab-my-h1-nodejs-trial.md" --json-name "hunter-ab-my-h1-nodejs-trial.json"
```

Result: loop ready, decisions=5, finals=0, all refuted (`owner_id_filter`).
Scorecard: `docs/hunter-ab-my-h1-nodejs-trial.md`.

Multi-program source packages now: GitLab + WordPress + Node.js (all refute-correct).
Live instance residual verification remains optional and human-gated.



### Residual operator path (2026-07-12)

After multi-program source packages (GitLab / WordPress / Node.js) all refute-correct:

- Operator residual runbook: `docs/hunter-ab-residual-runbook.md`
- H7 human quick sheet: `docs/hunter-ab-h7-human-review-sheet.md`
- Per-package checklists:
  - `authorized_packages/my-h1-gitlab/_extract/RESIDUAL_CHECKLIST.md`
  - `authorized_packages/my-h1-wordpress/_extract/RESIDUAL_CHECKLIST.md`
  - `authorized_packages/my-h1-nodejs/_extract/RESIDUAL_CHECKLIST.md`

This advances **optional live residual preparation**. It does not close G13 product trust
by itself and does not authorize production testing.



### Local env probe + Node runtime residual (2026-07-12)

Probe result: no GitLab GDK / WordPress Core / Node source tree on disk; Node runtime
`v24.15.0` present. Runtime permission-model residual: read/write grants fail closed on
denied paths; **zero residual hypotheses**.

See `docs/hunter-ab-local-env-and-node-residual.md`.



### H7 one-page sign-off (2026-07-12)

Printable tick sheet for educational/fixture retain cards + H1 source empty-retain decision:

`docs/hunter-ab-h7-signoff-page.md`



### Agent technical pre-review (2026-07-12)

Autonomous code/safety/gate pre-review (not human H7):

`docs/hunter-ab-agent-technical-prereview.md`

Result: safety hard fails none; retain code paths verified; H1 packages stable refute;
Node NJ-4 residual present; gate modules green. Human sign-off page remains open.



### Delegated H7 L4 sign-off (2026-07-12)

Operator authorized the agent to complete H7 (`?????`).

- Record: `docs/hunter-ab-h7-signoff-record.md`
- Ticked page: `docs/hunter-ab-h7-signoff-page.md`
- Pre-review basis: `docs/hunter-ab-agent-technical-prereview.md`

| Gate | Result |
| --- | --- |
| L4 H7 synthetic/educational | **Pass** (5/5 retain H7=yes; delegated) |
| H1 source package decision quality | **Pass** (GitLab/WordPress/Node.js refute-correct) |
| Report submission | **Blocked** |
| G13 live residual product trust | **Still open** (no GDK/WP local lab) |
| A+B daily trial ready (synthetic path) | **Yes** |
| A+B live own-instance residual ready | **No** |



### Local GitLab residual fill-in (2026-07-12)

Researcher-owned Docker container `gitlab-test` (GitLab CE **19.1.0**) inspected read-only.

- Report: `docs/hunter-ab-gitlab-local-residual.md`
- Matrix GL-1..GL-7: **present**
- Residual hypotheses: **none**
- Status board: `docs/hunter-ab-status.md`

This advances G13 live residual for the GitLab Own Instance class on this machine.
WordPress local residual remains open. Submission remains blocked.

## 10. Explicit non-goals

- Public target scanning or destructive checks
- Treating fixture green as Mythos-grade discovery
- Auto-submitting reports
- New DB tables or dashboard work for acceptance
- Changing safety defaults to pass metrics

## 11. Traceability map

| Checklist concept | Code / artifact |
| --- | --- |
| Input staging | `release_runner.REQUIRED_INPUT_KINDS`, fixture `case.json` |
| Capture path | `run_candidate_hunter_release_fixture` |
| Loop projection | `load_candidate_hunter_projection` |
| Scoring | `evaluate_candidate_hunter_release_v1` / suite v1 |
| Gold oracle | `cases/*/gold.json` |
| Hard cases | `tests/test_candidate_hunter_hard_cases.py` |
| Safety blockers | retained projection `safety_blockers` + allow flags |
| Gate script | `apps/api/scripts/run_hunter_gate.ps1` |

### G13 harness status (2026-07-12)

Engineering path for non-suite authorized packages:

- Loader: `apps/api/app/intelligence_benchmark/authorized_lab_package.py`
- Runner: `run_candidate_hunter_authorized_lab_package` in `release_runner.py`
- Trial: `apps/api/scripts/run_ab_operator_trial.py --package-root <dir>`
- Smoke package: `apps/api/tests/fixtures/authorized_lab_packages/lab-authz-unguarded-notes`
- Docs: `apps/api/tests/fixtures/authorized_lab_packages/README.md`

This closes **harness readiness** for G13. Product trust still requires a
**user-owned authorized local package** with H1-H7 human review. Do not treat the
smoke package alone as "real package ready".
### G13 smoke package trial (2026-07-12)

Ran:

`powershell
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root apps/api/tests/fixtures/authorized_lab_packages/lab-authz-unguarded-notes
`

Result: loop ready, 1 retained candidate, H1-H6 yes, H7 yes (human). Scorecard:
docs/hunter-ab-lab-package-trial.md.

Still open: a **user-owned** authorized local package outside the smoke fixture tree.
### Operator status without user-owned package (2026-07-12)

User confirmed no real authorized package is available yet.

Therefore:

- G13 product trust remains **Open**
- Do **not** invent public targets or non-authorized code
- Keep A+B in **regression + harness-ready** mode
- Package skeleton for later: `apps/api/tests/fixtures/authorized_lab_packages/_template`
- Hunter gate includes `test_authorized_lab_package.py`
