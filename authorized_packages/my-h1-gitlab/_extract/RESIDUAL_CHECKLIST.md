# Residual version-diff checklist (GitLab Own Instance / GDK)

Use only on researcher-owned GDK or self-managed GitLab. No gitlab.com production attacks.

Companion: `docs/hunter-ab-residual-runbook.md` ?3
Facts: `SOURCE_FACTS.md`
Filled report: `docs/hunter-ab-gitlab-local-residual.md`

## Version pin

- Local product version / commit: **GitLab CE 19.1.0** (Docker image `gitlab/gitlab-ce:latest`, container `gitlab-test`)
- Install type: Docker Omnibus-style CE (`/opt/gitlab/embedded/service/gitlab-rails`)
- Date checked: 2026-07-12
- Method: **static source residual inside researcher-owned container** (read local files only; no production host; no customer data export exercise)

## Control matrix

| ID | Control point | Status (present/changed/missing/alternate) | Notes |
| --- | --- | --- | --- |
| GL-1 | find_project! / read_project on project show | present | `find_project!` still requires `can?(current_user, read_project_ability, project)` with `:read_project` |
| GL-2 | job-auth project scope boundary | present | `authorized_project_scope?` compares `current_authenticated_job.project == project` when job_token_scope == :project |
| GL-3 | job-auth policy gate | present | `authorize_job_token_policies!` / `job_token_policies_authorized?` still called from `find_project!` |
| GL-4 | authorize_admin_project on export start/download | present | `API::ProjectExport` resource `before` calls `authorize_admin_project` before status/download/start routes |
| GL-5 | authorize_admin_project on export_relations | present | second resource block `before` also calls `authorize_admin_project` before relations export routes |
| GL-6 | authorize_read_code! on repository archive | present | `repositories.rb` `before { authorize_read_code! }`; archive route uses `send_git_archive` after rate limit |
| GL-7 | session/PAT/job-auth all hit hooks | present (code-path) | hooks live in shared helpers/`before`; auth-method matrix not HTTP-exercised this pass (static only) |

## Residual hypotheses (if any)

_None for naive missing-ownership / open export-by-id claims against this CE 19.1.0 source pin._

Optional non-vuln inventory notes (not report candidates by themselves):

1. Export download still serves via `present_carrierwave_file!` **after** admin-project authorization ? sink is guarded.
2. Relations export has additional feature-flag / bulk_import settings gate before admin-project authorize.
3. Full multi-auth HTTP matrix (session vs PAT vs job token) remains optional if you later do non-destructive local API checks with your own empty projects only.

## Safety

- [x] local-only target (Docker container `gitlab-test` on this machine)
- [x] no real user private data collected
- [x] no destructive tests / no mass export abuse
- [x] report submission blocked
- [x] no gitlab.com production probing

## Result

- [x] controls still hold (zero residual)
- [ ] residual hypothesis written for human review
