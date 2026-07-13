# A+B Residual Operator Runbook

Date: 2026-07-12

Purpose: turn G13 source-backed packages into **local residual verification** work without
public scanning, destructive tests, or automatic report submission.

Primary packages:

| Package | Program | Research class | Trial status |
| --- | --- | --- | --- |
| `authorized_packages/my-h1-gitlab` | gitlab | Own Instance / self-managed + public CE model | 5 decisions, 0 finals, all refuted |
| `authorized_packages/my-h1-wordpress` | wordpress | Core SOURCE_CODE | 4 decisions, 0 finals, all refuted |
| `authorized_packages/my-h1-nodejs` | nodejs | Core SOURCE_CODE | 5 decisions, 0 finals, all refuted |
| `authorized_packages/my-local-new-api` | local new-api | researcher-owned self-hosted OSS | 3 decisions, 0 finals, all refuted |

Related scorecards:

- `docs/hunter-ab-my-h1-gitlab-trial.md`
- `docs/hunter-ab-my-h1-wordpress-trial.md`
- `docs/hunter-ab-my-h1-nodejs-trial.md`
- `docs/hunter-ab-my-local-new-api-trial.md`
- `docs/hunter-ab-new-api-local-residual.md`
- H7 quick sheet: `docs/hunter-ab-h7-human-review-sheet.md`

## 0. Safety defaults (fail-closed)

Always true for this runbook:

1. Only researcher-owned / explicitly authorized local materials.
2. No gitlab.com production, wordpress.com, nodejs.org, or third-party customer assets.
3. No real user data, secrets, cookies, or Authorization headers in packages or notes.
4. No destructive validation, DoS, credential stuffing, or high-frequency scanning.
5. Mythos remains non-executing: no auto live validation, no auto report submit.
6. Hunter `refuted` is a decision signal, not a proof that a live residual cannot exist.
7. Residual findings stay hypotheses until human review and program policy fit.

## 1. When to use this runbook

Use it after a source-faithful package trial returns **finals=0 / all refuted**.

That outcome means:

- the **faithful model of public source** is guarded enough that naive ownership-gap
  candidates were correctly rejected;
- residual research value, if any, is in **version drift**, **alternate code paths**,
  **auth-method gaps**, **misconfiguration**, or **threat-model edge cases**.

Do **not** invent unguarded package inputs just to force a retain card.

## 2. Shared residual method (all three programs)

```text
1) Re-confirm program scope / policy class
2) Pin local version (tag, commit, or install version)
3) Diff SOURCE_FACTS control points against that version
4) Mark each control point: present / changed / missing / alternate path
5) Only for changed/missing/alternate: write a hypothesis card
6) Prefer static proof + open-source reproduction plan
7) Human H1-H7; submission blocked by default
```

### Hypothesis card minimum fields

- program + asset class
- local version pin
- control point expected vs observed
- affected route or function
- why current public model may not cover it
- refutation questions
- non-destructive validation plan
- safety blockers
- report_submission_allowed = false

## 3. GitLab residual (Own Instance / GDK / self-managed)

Package facts: `authorized_packages/my-h1-gitlab/_extract/SOURCE_FACTS.md`  
Per-package checklist: `authorized_packages/my-h1-gitlab/_extract/RESIDUAL_CHECKLIST.md`

### Authorization class

- Prefer local GDK or researcher-owned self-managed GitLab.
- Public CE sources model expected controls; they are not gitlab.com exploit scripts.

### Control points to re-check on installed version

| ID | Control point | Expected in public CE model |
| --- | --- | --- |
| GL-1 | Project show path | `user_project` / `find_project!` + `can?(:read_project)` |
| GL-2 | Job-auth project scope | job-auth cannot cross project ids when scoped |
| GL-3 | Job-auth policies | policies_allowed style gate for non-public features |
| GL-4 | Export start/status/download | `authorize_admin_project` before export sinks |
| GL-5 | Export relations | same admin-project before relations export |
| GL-6 | Repository archive | `authorize_read_code!` before archive send |
| GL-7 | Auth methods | session / PAT / job-auth all still hit the above hooks |

### Residual questions (local only)

1. Does your installed version still run `authorize_admin_project` on export download?
2. Is there an alternate export/download path that skips the before hook?
3. Does job-auth still fail closed across project boundaries?
4. Are public vs private project visibility rules still applied in `find_project!`?
5. Did a backport/patch remove or reorder any of GL-1..GL-7?

### Stop conditions

- Stop if you only have gitlab.com production access and no local instance.
- Stop before any customer-data export, mass cloning, or rate-abuse testing.

## 4. WordPress residual (Core SOURCE_CODE / local Core tree)

Package facts: `authorized_packages/my-h1-wordpress/_extract/SOURCE_FACTS.md`  
Per-package checklist: `authorized_packages/my-h1-wordpress/_extract/RESIDUAL_CHECKLIST.md`

### Authorization class

- WordPress Core SOURCE_CODE local review under HackerOne wordpress.
- Not wordpress.com and not other people's sites.

### Control points to re-check on local Core version

| ID | Control point | Expected in public Core model |
| --- | --- | --- |
| WP-1 | Object load | `get_post` invalid id -> error, not silent open sink |
| WP-2 | Read gate | `get_item_permissions_check` -> `check_read_permission` |
| WP-3 | Update gate | `update_item_permissions_check` -> `check_update_permission` / `edit_post` |
| WP-4 | Delete gate | `delete_item_permissions_check` -> `check_delete_permission` / `delete_post` |
| WP-5 | Author change | author reassignment needs elevated capability |
| WP-6 | Status rules | publish/public vs draft/private ownership-style boundary |

### Residual questions (local only)

1. Did your Core version change any of WP-1..WP-6 method names or call order?
2. Is there another controller (custom post type / attachments / users) with weaker gates?
3. Are plugin overrides in scope for your research goal? If not, keep Core-only.
4. Can you show a Core path where id reaches a sensitive sink without the capability check?

### Stop conditions

- Stop at other people's WordPress sites.
- Treat plugin-only issues as a different scope decision, not this Core package residual.

## 5. Node.js residual (Core SOURCE_CODE / local Node tree)

Package facts: `authorized_packages/my-h1-nodejs/_extract/SOURCE_FACTS.md`  
Per-package checklist: `authorized_packages/my-h1-nodejs/_extract/RESIDUAL_CHECKLIST.md`

### Authorization class

- Node.js core SOURCE_CODE only; project websites are not IBB-eligible.
- Permission Model is opt-in defense-in-depth for trusted application code.

### Control points to re-check on local Node version

| ID | Control point | Expected in public core model |
| --- | --- | --- |
| NJ-1 | Permission API | `isEnabled` / `has` / `drop` still present |
| NJ-2 | FS read gate | path reads deny when model enabled and `fs.read` missing |
| NJ-3 | FS write gate | write-class ops require `fs.write` grants |
| NJ-4 | Symlink gate | symlink requires full `fs` when model enabled |
| NJ-5 | Grant trees | separate read/write trees; deny_all / allow_all semantics |
| NJ-6 | Threat-model docs | SECURITY.md non-vuln boundaries still match behavior |

### Residual questions (local only)

1. Did a local/versioned build drop or weaken NJ-2..NJ-4 for some path APIs?
2. Is an alternate binding/path normalization skipping grant lookup?
3. Is the issue actually outside the Node threat model (operator flags, intentional grants)?
4. Can it be reproduced with open-source tools only?

### Classification discipline (high importance)

- Operator-controlled flags are usually operator responsibility, not automatic core vulns.
- Symlink/realpath into an already-allowed path is usually intended.
- Prefer reports that violate published threat-model policy with OSS reproduction.

## 6. How residual maps back into Mythos-Lite

Recommended loop:

```text
residual note (markdown)
  -> optional new package inputs only if you have authorized local code evidence
  -> run_ab_operator_trial.py --package-root ...
  -> H1-H7 human review
  -> still submission-blocked
```

Do not:

- replace guarded source models with unguarded stubs to force retain;
- store live secrets or production HAR with cookies;
- claim G13 closed solely because residual checklists exist.

## 7. Pass / fail for residual work

| Gate | Pass means |
| --- | --- |
| R0 Safety | No out-of-scope host, no real user data, no destructive action |
| R1 Version pin | Local version/commit recorded |
| R2 Control matrix | Every control ID marked present/changed/missing/alternate |
| R3 Hypothesis quality | Any remaining claim has endpoint/path + refute Q + safe plan |
| R4 Human | H7 filled; submission remains blocked |

Residual work can pass even with **zero** residual hypotheses. That is a valid result:
public controls still hold on the local pin.

## 8. Suggested operator order

1. Run H7 sheet on educational retain packages (10 minutes).
2. Pick **one** residual track with a real local pin:
   - Node source tree if you already develop with Node; or
   - GitLab GDK if you can install it; or
   - WordPress Core checkout if lighter weight.
3. Complete that program's control matrix before starting another.
4. Only package a new Mythos input set when residual evidence is concrete.

## 9. Commands (local package re-trial only)

```powershell
cd "C:\Users\Administrator\Desktop\Bounty Mythos-Lite"
$base = "apps\api\.pytest-tmp"; $env:TEMP=$base; $env:TMP=$base; $env:PYTHONPATH="apps\api"

.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root "authorized_packages\my-h1-gitlab" --md-name "hunter-ab-my-h1-gitlab-trial.md" --json-name "hunter-ab-my-h1-gitlab-trial.json"
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root "authorized_packages\my-h1-wordpress" --md-name "hunter-ab-my-h1-wordpress-trial.md" --json-name "hunter-ab-my-h1-wordpress-trial.json"
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root "authorized_packages\my-h1-nodejs" --md-name "hunter-ab-my-h1-nodejs-trial.md" --json-name "hunter-ab-my-h1-nodejs-trial.json"
```

These commands re-check hunter decision quality on the packages. They do **not** replace
version-diff residual work on your installed software.

## 7. Local DVWA residual (researcher-owned lab) — done 2026-07-12

Package: `authorized_packages/my-local-dvwa`  
Report: `docs/hunter-ab-dvwa-local-residual.md`  
Trial: `docs/hunter-ab-my-local-dvwa-trial.md`

- Container `mythos-dvwa` / `vulnerables/web-dvwa` / bind `127.0.0.1:8080`
- Method: read-only source inspect + hunter retain trial on unguarded object-id export model
- Result: intentional teaching defects only; **0 unexpected residual**; submission blocked

## 8. Local Juice Shop residual (researcher-owned lab) — done 2026-07-12

Package: `authorized_packages/my-local-juice-shop`  
Report: `docs/hunter-ab-juice-shop-local-residual.md`  
Trial: `docs/hunter-ab-my-local-juice-shop-trial.md`

- Public MIT `routes/basket.ts` `retrieveBasket`: load-by-id without ownership deny before response
- Result: intentional challenge only; **0 unexpected residual**; submission blocked

## 9. WordPress Core residual — done 2026-07-12

Package: `authorized_packages/my-h1-wordpress`  
Report: `docs/hunter-ab-wordpress-local-residual.md`  
Pin: Core **7.1-alpha-62695** public tree REST posts controller  

- WP-1..WP-6 **present**
- **0 residual hypotheses** on Core REST posts surface
- Aligns with package trial 4/0 refuted
