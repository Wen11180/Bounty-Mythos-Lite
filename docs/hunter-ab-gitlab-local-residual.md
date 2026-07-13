# Local GitLab CE residual (researcher-owned Docker)

Date: 2026-07-12T08:17:20Z

## Why this is in scope for residual work

- HackerOne GitLab program encourages local / self-managed research classes.
- Container `gitlab-test` is running on this operator machine (`gitlab/gitlab-ce:latest`).
- Work performed: **read-only static inspection of files inside the local container**.
- Not performed: production probing, destructive validation, credential stuffing, or automatic report submission.

## Version pin

| Field | Value |
| --- | --- |
| Container | `gitlab-test` |
| Image | `gitlab/gitlab-ce:latest` |
| Product | GitLab CE **19.1.0** |
| Rails tree | `/opt/gitlab/embedded/service/gitlab-rails` |
| Package model | `authorized_packages/my-h1-gitlab` (trial 5 decisions / 0 finals / all refuted) |

## Control matrix vs package SOURCE_FACTS

| ID | Package expectation | CE 19.1.0 local observation | Status |
| --- | --- | --- | --- |
| GL-1 | find_project! + can read_project | Confirmed in `lib/api/helpers.rb` `find_project!` | present |
| GL-2 | job-auth project scope | `authorized_project_scope?` still enforces job project equality | present |
| GL-3 | job-auth policies | `authorize_job_token_policies!` still invoked | present |
| GL-4 | export behind authorize_admin_project | `lib/api/project_export.rb` before hook | present |
| GL-5 | export_relations behind authorize_admin_project | second before block in same file | present |
| GL-6 | repository archive behind authorize_read_code! | `lib/api/repositories.rb` before + archive route | present |
| GL-7 | hooks shared across auth methods | helpers/`before` architecture unchanged | present (static) |

### Evidence excerpts (local container paths)

- `project_export.rb`: `before do ... authorize_admin_project end` wrapping export status/download/start
- `project_export.rb`: relations resource also `authorize_admin_project` in `before`
- `helpers.rb`: `authorize_admin_project -> authorize!(:admin_project, user_project)`
- `helpers.rb`: `authorize_read_code! -> authorize!(:read_code, user_project)`
- `helpers.rb`: `find_project!` still chains scope + `can?(:read_project)` + job-token policies
- `repositories.rb`: top-level `before { authorize_read_code! }`; archive uses `send_git_archive`

## Residual hypotheses

**None.**

Faithful Mythos package refute outcomes remain consistent with this local CE pin: naive missing-ownership / open export-by-id claims should not be retained against current source.

## Gates

| Gate | Result |
| --- | --- |
| R0 Safety | **Pass** |
| R1 Version pin | **Pass** (CE 19.1.0) |
| R2 Control matrix | **Pass** GL-1..GL-7 present |
| R3 Hypothesis quality | **Pass** (zero residual claims) |
| R4 Human | recorded under delegated A+B program residual notes; submission blocked |

## Explicit non-claims

- This does not prove absence of all GitLab vulnerabilities.
- This does not authorize testing gitlab.com or other tenants.
- This does not replace multi-auth live matrix testing with owned empty projects (optional later, still non-destructive).
- This does not unlock report submission.

## Linkage to A+B status

- H1 package trial: still refute-correct
- Live residual for GitLab Own Instance class: **controls hold on this machine pin**
- Remaining live residual gaps: WordPress Core local tree (still absent)
