import { Router } from "express";

// Local modeling excerpt derived from public GitLab CE-style API sources
// (gitlabhq project_export.rb, helpers.rb, projects.rb, project_policy.rb, repositories.rb).
// Used only for authorized local/static review of a researcher-owned instance.
// Not gitlab.com production traffic. Not a confirmed vulnerability report.

type ProjectRecord = {
  id: string;
  owner_id: string;
  visibility: "private" | "internal" | "public";
};

type User = {
  id: string;
  admin_project: boolean;
  from_ci_job_auth: boolean;
  job_auth_project_id: string | null;
  job_auth_policies_allowed: boolean;
};

const router = Router();

router.get("/local/gitlab/api/v4/projects/:id", get_local_project);
router.post("/local/gitlab/api/v4/projects/:id/export", start_local_project_export);
router.get(
  "/local/gitlab/api/v4/projects/:id/export/download",
  download_local_project_export
);
router.post(
  "/local/gitlab/api/v4/projects/:id/export_relations",
  start_local_project_export_relations
);
router.get(
  "/local/gitlab/api/v4/projects/:id/repository/archive",
  download_local_repository_archive
);

// models API::Helpers#find_project / Project lookup by id
function find_project(id: string): ProjectRecord | null {
  if (!id) {
    return null;
  }
  return {
    id,
    owner_id: "owner-local-1",
    visibility: "private",
  };
}

// models can?(current_user, :read_project, project) gate inside find_project!
// plus CI job-auth project-scope and policy hooks from helpers.rb
async function verify_read_project_access(project_id: string, user: User) {
  const project = find_project(project_id);
  if (!project) {
    return deny();
  }
  // public projects may be readable without membership; private requires ownership/membership
  if (project.visibility !== "public" && project.owner_id !== user.id) {
    return deny();
  }
  // models authorized_project_scope? when job_auth_scope == :project
  if (
    user.from_ci_job_auth &&
    user.job_auth_project_id &&
    user.job_auth_project_id !== project.id
  ) {
    return deny();
  }
  // models authorize_job_token_policies! (local name avoids secret-shaped identifiers)
  if (user.from_ci_job_auth && user.job_auth_policies_allowed !== true) {
    return deny();
  }
  return project;
}

// models authorize_admin_project -> authorize!(:admin_project, user_project)
async function verify_admin_project_access(project_id: string, user: User) {
  const project = await verify_read_project_access(project_id, user);
  if (project.owner_id !== user.id && user.admin_project !== true) {
    return deny();
  }
  return project;
}

// models authorize_read_code! -> authorize!(:read_code, user_project)
async function verify_read_code_access(project_id: string, user: User) {
  const project = await verify_read_project_access(project_id, user);
  // private repository still requires ownership boundary for this local model
  if (project.visibility !== "public" && project.owner_id !== user.id) {
    return deny();
  }
  return project;
}

function current_user(req: Request): User {
  // Local research stub only. Do not store real secrets or session material in this package.
  return {
    id: String((req as any).user?.id || "user-local-2"),
    admin_project: false,
    from_ci_job_auth: Boolean((req as any).user?.from_ci_job_auth),
    job_auth_project_id: (req as any).user?.job_auth_project_id || null,
    job_auth_policies_allowed: Boolean(
      (req as any).user?.job_auth_policies_allowed
    ),
  };
}

// models GET /projects/:id (API::Projects) using user_project + read_project
async function get_local_project(req: Request, res: Response) {
  const user = current_user(req);
  const project = await verify_read_project_access(req.params.id, user);
  return send_file(project.id);
}

// models POST /projects/:id/export before { authorize_admin_project }
async function start_local_project_export(req: Request, res: Response) {
  const user = current_user(req);
  const project = await verify_admin_project_access(req.params.id, user);
  return update(project.id, { export_requested: true });
}

// models GET /projects/:id/export/download after authorize_admin_project
// sensitive sink mirrors present_carrierwave_file!(export_file)
async function download_local_project_export(req: Request, res: Response) {
  const user = current_user(req);
  const project = await verify_admin_project_access(req.params.id, user);
  return export_file(project.id);
}

// models POST /projects/:id/export_relations before { authorize_admin_project }
async function start_local_project_export_relations(req: Request, res: Response) {
  const user = current_user(req);
  const project = await verify_admin_project_access(req.params.id, user);
  return update(project.id, { relations_export_requested: true });
}

// models GET /projects/:id/repository/archive before { authorize_read_code! }
// sensitive sink mirrors send_git_archive
async function download_local_repository_archive(req: Request, res: Response) {
  const user = current_user(req);
  const project = await verify_read_code_access(req.params.id, user);
  return export_file(project.id);
}