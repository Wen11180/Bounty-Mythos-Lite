# Extracted facts from public GitLab CE-style API sources

Fetched for local authorized research under HackerOne gitlab local/self-managed research class.
Upstream files stored under _upstream/ (not loaded by Mythos package inputs).

## project_export.rb (API::ProjectExport)
- resource projects/:id
- before hook:
  - not_found unless project_export_enabled
  - authorize_admin_project
- GET :id/export -> present export status via user_project
- GET :id/export/download -> rate limit, export_file_exists?, present_carrierwave_file!(export_file)
- POST :id/export -> rate limit, add_export_job
- relations export resource also before { authorize_admin_project }
- POST :id/export_relations / GET download / GET status
- route_setting permissions: read_project_export / download_project_export / create_project_export / create_project_relation_export

## helpers.rb
- user_project -> find_project!(params[:id])
- find_project(id) looks up Project by integer id or full path within find_project_scopes
- find_project! returns not_found if missing; checks can?(current_user, read_project_ability, project)
- find_project! enforces authorized_project_scope? for job tokens and authorize_job_token_policies!
- authorize_admin_project -> authorize!(:admin_project, user_project)
- authorize_read_code! -> authorize!(:read_code, user_project)
- job_token_policies_authorized? requires policies_allowed for non-public features when from_ci_job_token?

## repositories.rb
- before { authorize_read_code! }
- GET :id/repository/archive -> check_archive_rate_limit!, send_git_archive / send_git_archive_head
- route_setting permissions: read_repository_archive

## projects.rb
- GET :id retrieve project uses user_project and read_project permission route_setting
- public projects may be accessible without auth per API detail text

## project_policy.rb
- guest enables :read_project
- admin_project appears in elevated permission sets
- job-token rules prevent_all for disallowed private project job-token access with limited public exceptions
- export-specific abilities are enforced at API authorize_admin_project boundary in ProjectExport

## Research implications for local instance review
1. Export download is not an unauthenticated open sink in current public source: it is behind authorize_admin_project.
2. Object resolution is centralized in find_project!/user_project with can?(:read_project) plus job-token scope/policy.
3. Repository archive is behind authorize_read_code!, not open by id alone.
4. Local instance review should verify these hooks still run in the deployed version and for all auth methods (session, PAT, job token).
5. Mythos candidates from a faithful model should often REFUTE naive "missing ownership" if guards are observed; residual risk is misconfiguration, version drift, or alternate code paths.
