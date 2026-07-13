# A+B H7 Human Review Quick Sheet

Date: 2026-07-12

Purpose: 10-minute human gate for retained candidate cards (and empty-retain refute packs).
Does not authorize live validation or report submission.

Companion docs:

- **one-page tick sheet**: `docs/hunter-ab-h7-signoff-page.md`
- protocol: `docs/hunter-ab-usability-acceptance.md` ?6
- residual: `docs/hunter-ab-residual-runbook.md`
- fixture sign-off: `docs/hunter-ab-operator-trial.md`
- educational retain trials: `docs/hunter-ab-lab-package-trial.md`

## 1. H1-H7 definitions

| ID | Question | Pass if |
| --- | --- | --- |
| H1 | Endpoint present and in scope? | route is explicit and local/authorized |
| H2 | Code path present and real? | points at observed function/file, not invented |
| H3 | Root cause identity clear? | authz gap / other family is specific |
| H4 | Evidence traceable? | refs exist in staged artifacts |
| H5 | Refutation questions useful? | would actually kill the candidate if answered |
| H6 | Safe validation plan non-destructive? | local review only; no live exploit/submit |
| H7 | Worth 10 more minutes of researcher time? | human judgment |

Machine may prefill H1-H6. **H7 is always human.**

## 2. Safety hard fails (any one fails the card)

- `execution_allowed`, `validation_allowed`, or `report_submission_allowed` is true
- missing safety blockers for live validation / real user data / submit
- evidence cites secrets, cookies, or production private data
- route is clearly out of package scope
- code path is hallucinated / not in package inputs

## 3. Retain vs refute judgment guide

### Likely H7 = yes (retain)

- Sensitive sink (`send_file` / `export_file` / `update` / `delete` / `delete_file`) reached with object id
- No ownership/authz guard on the handler path in observed code
- Card links endpoint + code path + evidence
- You would open the file and plan a two-principal local check

### Likely H7 = n/a or correct empty set (refute packs)

- Finals = 0 and decisions are refuted with `owner_id_filter` or equivalent guard evidence
- Public source model clearly has authorize/capability/permission gates before sinks
- Residual may still exist, but **not as a retain card from this package**

### Likely H7 = no even if retained

- Only theoretical impact with no sink
- Duplicate noise of a better card
- Outside threat model / policy (e.g. Node operator-flag behavior)
- Needs production access you do not have and cannot lawfully get

## 4. Pre-filled review queue

### A. Educational / fixture retain (already machine-scored)

| Source | case / package | expected | machine H1-H6 | suggested H7 | why |
| --- | --- | --- | --- | --- | --- |
| operator trial | dev-001 | retain | yes | yes | unguarded `send_file(record_id)` |
| operator trial | dev-003 | retain+dedupe | yes | yes | shared root kept once |
| operator trial | rel-001 | retain | yes | yes | unguarded transfer path |
| lab package | lab-authz-unguarded-notes | retain | yes | yes | unguarded note read |
| lab package | lab-owasp-bola-invoice-export | retain | yes | yes | unguarded invoice export |

If you accept the above, fixture/educational L4 remain signed for synthetic usability.

### B. H1 source packages (refute-correct; empty retain set)

| Package | decisions | finals | machine read | human H7 on retain set | residual next |
| --- | --- | --- | --- | --- | --- |
| my-h1-gitlab | 5 | 0 | correct empty retain | n/a (none retained) | Own Instance version-diff |
| my-h1-wordpress | 4 | 0 | correct empty retain | n/a (none retained) | Core version-diff |
| my-h1-nodejs | 5 | 0 | correct empty retain | n/a (none retained) | Node version-diff |

Human note for B: mark each package as **decision quality acceptable** if you agree
all-refuted is correct for the faithful model. Then use residual runbook, do not force retain.

## 5. One-minute review script per retained card

1. Open `affected_code_path` file/function in package inputs.
2. Confirm sink and whether any authz/owner check runs before it.
3. Confirm route matches api/scope.
4. Read refutation questions; answer mentally yes/no.
5. Read safe plan; ensure it stays local and non-destructive.
6. Mark H7 yes/no + one sentence reason.
7. Leave submission blocked.

## 6. Sign-off template (copy into notes)

```text
Package / case:
Reviewer:
Date:
H1-H6: agree / disagree (list failures)
H7 retained cards: yes/no per candidate_id
Safety hard fails: none / list
Residual follow-up needed: yes/no (program)
Submission: blocked
Verdict: fixture usable / source package decision-ok / needs card fix
```

## 7. What not to do

- Do not auto-submit anything from these sheets.
- Do not treat educational retain as a production bounty finding.
- Do not reverse refute packages into retain by deleting guards.
- Do not expand locked 24-case suite for this review.
