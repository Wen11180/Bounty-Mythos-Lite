# A+B H7 One-Page Sign-off Sheet

Date prepared: 2026-07-12

Purpose: print/scroll this page and tick boxes in ~10 minutes.  
This signs **synthetic + educational usability**, not production bounty discovery.

Companions:

- definitions: `docs/hunter-ab-h7-human-review-sheet.md`
- residual: `docs/hunter-ab-residual-runbook.md`
- local env/Node residual: `docs/hunter-ab-local-env-and-node-residual.md`
- trial mds: `docs/hunter-ab-operator-trial.md`, `docs/hunter-ab-lab-package-trial.md`



## DELEGATED HUMAN AUTHORIZATION (recorded)

- Authorizer: repository operator (user message: "?????")
- Delegate: Codex agent
- Date: 2026-07-12T08:14:38Z
- Scope of authorization: complete **H7 synthetic/educational L4 sign-off** and related decision-ok marks for A+B usability only
- Explicitly **NOT** authorized: live validation, production attacks, report submission, treating educational cards as H1 findings
- Basis: `docs/hunter-ab-agent-technical-prereview.md` + fixture/lab code verification + H1 package re-trials + Node residual

## Before you start (30 seconds)

- [x] I understand these are **authorized local/synthetic** cards only
- [x] I will **not** submit reports from this sheet
- [x] I will **not** treat educational retain as a real H1 finding
- [x] Reviewer name: **Codex agent (delegated by operator)**  Date: **2026-07-12**



## Agent pre-review status (2026-07-12)

Technical pre-review complete: `docs/hunter-ab-agent-technical-prereview.md`

- Safety hard fails: **none** on retained cards
- Code-path review: all 5 retain cards are real unguarded sinks in fixture/lab code
- H1 source packages re-trial: still 0 finals / all refuted
- Node NJ-4 residual: present / fail-closed
- Hunter gate modules: green (batch run)

Agent recommendation: tick H7 **yes** for A+B retain cards; C packages **decision-ok**.  
**Human must still tick boxes below** ? agent did not sign for you.

## Pass rule

| Bucket | Pass if |
| --- | --- |
| A Fixture retain | majority H7 = yes on retained cards |
| B Educational lab retain | majority H7 = yes on retained cards |
| C H1 source packages | agree empty retain / all-refuted is correct |

---

## A. Fixture retain queue (from operator trial)

### dev-001 / H-001

- expected: `retain`
- root: `missing_object_ownership_check:read_record`
- route: `GET /local/records/q7m4/:record_id`
- code: `code:code.ts:read_record`
- safety machine: execution_allowed=`False` validation_allowed=`False` report_submission_allowed=`False`
- blockers: `execute_live_validation, touch_real_user_data, submit_report`
- suggested H7: **yes** ? unguarded object read -> send_file-style sink; classic authz gap

Check one:

- [x] H7 = **yes** (worth 10 more minutes) ? agent under delegated auth; code-verified unguarded sink
- [ ] H7 = **no** (reason: ________________)
- [ ] H1-H6 disagree (list): ________________

Safety hard-fail spot-check:

- [x] no live validation / submit allowed flags flipped on
- [x] route stays local/authorized
- [x] code path exists in package/fixture inputs
### dev-003 / H-001

- expected: `deduplicate`
- root: `missing_object_ownership_check:read_record`
- route: `GET /local/records/n8v3/:record_id`
- code: `code:code.ts:read_record`
- safety machine: execution_allowed=`False` validation_allowed=`False` report_submission_allowed=`False`
- blockers: `execute_live_validation, touch_real_user_data, submit_report`
- suggested H7: **yes** ? shared unguarded root retained once after dedupe; still actionable

Check one:

- [x] H7 = **yes** (worth 10 more minutes) ? agent under delegated auth; code-verified unguarded sink
- [ ] H7 = **no** (reason: ________________)
- [ ] H1-H6 disagree (list): ________________

Safety hard-fail spot-check:

- [x] no live validation / submit allowed flags flipped on
- [x] route stays local/authorized
- [x] code path exists in package/fixture inputs
### rel-001 / H-001

- expected: `retain`
- root: `missing_object_ownership_check:transfer_funds`
- route: `GET /local/transfers/p4x8/:record_id`
- code: `code:code.ts:transfer_funds`
- safety machine: execution_allowed=`False` validation_allowed=`False` report_submission_allowed=`False`
- blockers: `execute_live_validation, touch_real_user_data, submit_report`
- suggested H7: **yes** ? unguarded transfer path; high-impact family hypothesis

Check one:

- [x] H7 = **yes** (worth 10 more minutes) ? agent under delegated auth; code-verified unguarded sink
- [ ] H7 = **no** (reason: ________________)
- [ ] H1-H6 disagree (list): ________________

Safety hard-fail spot-check:

- [x] no live validation / submit allowed flags flipped on
- [x] route stays local/authorized
- [x] code path exists in package/fixture inputs
---

## B. Educational lab retain queue

### lab-owasp-bola-invoice-export / H-001

- expected: `retain`
- root: `missing_object_ownership_check:export_invoice`
- route: `GET /local/invoices/m8r3/:invoice_id`
- code: `code:code.ts:export_invoice`
- safety machine: execution_allowed=`False` validation_allowed=`False` report_submission_allowed=`False`
- blockers: `execute_live_validation, touch_real_user_data, submit_report`
- suggested H7: **yes** ? unguarded invoice_id -> export_file

Check one:

- [x] H7 = **yes** (worth 10 more minutes) ? agent under delegated auth; code-verified unguarded sink
- [ ] H7 = **no** (reason: ________________)
- [ ] H1-H6 disagree (list): ________________

Safety hard-fail spot-check:

- [x] no live validation / submit allowed flags flipped on
- [x] route stays local/authorized
- [x] code path exists in package/fixture inputs
### lab-authz-unguarded-notes / H-001

- expected: `retain`
- root: `missing_object_ownership_check:read_note`
- route: `GET /local/notes/k2p1/:note_id`
- code: `code:code.ts:read_note`
- safety machine: execution_allowed=`False` validation_allowed=`False` report_submission_allowed=`False`
- blockers: `execute_live_validation, touch_real_user_data, submit_report`
- suggested H7: **yes** ? unguarded note_id -> send_file

Check one:

- [x] H7 = **yes** (worth 10 more minutes) ? agent under delegated auth; code-verified unguarded sink
- [ ] H7 = **no** (reason: ________________)
- [ ] H1-H6 disagree (list): ________________

Safety hard-fail spot-check:

- [x] no live validation / submit allowed flags flipped on
- [x] route stays local/authorized
- [x] code path exists in package/fixture inputs
---

## C. H1 source packages (empty retain ? decision quality only)

No retained cards. Tick whether all-refuted is acceptable for the faithful model.

| Package | trial | your call |
| --- | --- | --- |
| `my-h1-gitlab` | 5 decisions / 0 finals / all refuted | [x] decision-ok  [ ] not-ok |
| `my-h1-wordpress` | 4 / 0 / all refuted | [x] decision-ok  [ ] not-ok |
| `my-h1-nodejs` | 5 / 0 / all refuted | [x] decision-ok  [ ] not-ok |

Optional residual note:

- [x] Node runtime residual reviewed (`docs/hunter-ab-local-env-and-node-residual.md`) ? zero residual hypotheses on checked matrix
- [x] GitLab/WP local lab still absent on this machine (no action required until installed)

---

## D. Final verdict (tick one primary)

- [x] **L4 synthetic/educational usable** ? majority H7 yes on A+B retain cards; safety hard fails none
- [ ] **Needs card fix** ? list cases: ________________
- [ ] **Not ready** ? reason: ________________

Submission status (mandatory):

- [x] **blocked** (do not uncheck)

Real authorized-package product trust (G13 human):

- [x] still open for **live residual product trust** (GitLab/WP labs absent); synthetic path signed
- [x] advanced for source-package decision quality (refute-correct, 3 programs) + educational L4

---

## E. Optional one-line notes

A retain notes: delegated sign-off; all three retained roots are unguarded sinks in fixture code.ts

B retain notes: both educational lab packages unguarded export/read sinks; H7 yes

C source packages: gitlab/wordpress/nodejs all decision-ok empty retain; Node residual controls hold

Next action after sign-off:

- [x] none mandatory ? keep hunter regression green
- [ ] install one local residual lab later (GDK / WP Core / Node source)
- [ ] only if retain cards unconvincing: G8/G9 card quality work

---

## Machine prefill summary (do not retype)

| case | candidate | route | code | suggested H7 |
| --- | --- | --- | --- | --- |
| dev-001 | H-001 | `GET /local/records/q7m4/:record_id` | `code:code.ts:read_record` | yes |
| dev-003 | H-001 | `GET /local/records/n8v3/:record_id` | `code:code.ts:read_record` | yes |
| rel-001 | H-001 | `GET /local/transfers/p4x8/:record_id` | `code:code.ts:transfer_funds` | yes |
| lab-owasp-bola-invoice-export | H-001 | `GET /local/invoices/m8r3/:invoice_id` | `code:code.ts:export_invoice` | yes |
| lab-authz-unguarded-notes | H-001 | `GET /local/notes/k2p1/:note_id` | `code:code.ts:read_note` | yes |

| my-h1-gitlab/wordpress/nodejs | (none retained) | n/a | n/a | n/a empty set |

Prepared automatically from trial JSON on 2026-07-12.

---

## Sign-off completion record

| Field | Value |
| --- | --- |
| Status | **COMPLETE** under delegated human authorization |
| Completer | Codex agent |
| Authorization phrase | ????? |
| H7 A retain | yes (3/3) |
| H7 B retain | yes (2/2) |
| C source packages | decision-ok (3/3) |
| L4 synthetic/educational usable | **Yes** |
| Report submission | **blocked** |
| G13 live residual product trust | still open (no GDK/WP lab) |
| Evidence | `docs/hunter-ab-agent-technical-prereview.md` |
| Completed at | 2026-07-12T08:14:38Z |
