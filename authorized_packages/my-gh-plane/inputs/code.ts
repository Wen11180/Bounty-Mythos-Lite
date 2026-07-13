import { Router } from "express";

// Local modeling excerpt derived from public makeplane/plane v1.3.1 sources:
// - apps/api/plane/app/permissions/base.py allow_permission
// - apps/api/plane/app/views/issue/base.py retrieve / partial_update / destroy
// Faithful simplified model:
//   - Project membership: group_id === project scope
//   - Creator short-circuit: owner_id (created_by) === user.id
//   - retrieve: role guest+ OR creator
//   - partial_update: role member+ OR creator
//   - destroy: role admin OR creator
// Fail closed: deny() when neither creator nor required project role.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type IssueRecord = {
  id: string;
  // models Issue.created_by
  owner_id: string;
  // models project_id membership scope
  group_id: string;
  title: string;
};

type LabUser = {
  id: string;
  // models ProjectMember.project_id for active membership
  group_id: string;
  // models ROLE.GUEST+ for retrieve (role >= 5 with project membership)
  has_project_read: boolean;
  // models ROLE.MEMBER+ for partial_update (role >= 15)
  has_project_write: boolean;
  // models ROLE.ADMIN for destroy (role >= 20) or workspace admin shortcut residual
  has_project_admin: boolean;
};

const router = Router();

router.get(
  "/local/plane/api/projects/:project_id/issues/:id",
  get_local_plane_issue,
);
router.patch(
  "/local/plane/api/projects/:project_id/issues/:id",
  update_local_plane_issue,
);
router.delete(
  "/local/plane/api/projects/:project_id/issues/:id",
  delete_local_plane_issue,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    group_id: String((req as any).user?.group_id || "project-lab-2"),
    has_project_read: Boolean((req as any).user?.has_project_read ?? false),
    has_project_write: Boolean((req as any).user?.has_project_write ?? false),
    has_project_admin: Boolean((req as any).user?.has_project_admin ?? false),
  };
}

// models Issue.objects.filter(project_id, workspace slug, pk)
function find_issue(issue_id: string, project_id: string): IssueRecord | null {
  if (!issue_id || !project_id) {
    return null;
  }
  return {
    id: issue_id,
    owner_id: "owner-lab-1",
    group_id: project_id || "project-lab-1",
    title: "lab-issue",
  };
}

// models creator=True branch: model.objects.filter(id=pk, created_by=request.user)
function is_creator(issue: IssueRecord, user: LabUser): boolean {
  // owner_id_filter: Issue.created_by short-circuit
  return issue.owner_id === user.id;
}

// models ProjectMember role filter for project_id
function has_project_membership(issue: IssueRecord, user: LabUser): boolean {
  // group_id_filter: must belong to same project
  return issue.group_id === user.group_id;
}

// models @allow_permission([ADMIN, MEMBER, GUEST], creator=True, model=Issue)
async function verify_issue_read_access(
  issue_id: string,
  project_id: string,
  user: LabUser,
) {
  const issue = find_issue(issue_id, project_id);
  if (!issue) {
    return deny();
  }
  // creator short-circuit first
  if (is_creator(issue, user)) {
    return issue;
  }
  // group_id_filter + role
  if (!has_project_membership(issue, user)) {
    return deny();
  }
  if (!user.has_project_read) {
    return deny();
  }
  return issue;
}

// models @allow_permission([ADMIN, MEMBER], creator=True, model=Issue)
async function verify_issue_update_access(
  issue_id: string,
  project_id: string,
  user: LabUser,
) {
  const issue = find_issue(issue_id, project_id);
  if (!issue) {
    return deny();
  }
  if (is_creator(issue, user)) {
    return issue;
  }
  if (!has_project_membership(issue, user)) {
    return deny();
  }
  if (!user.has_project_write) {
    return deny();
  }
  return issue;
}

// models @allow_permission([ADMIN], creator=True, model=Issue)
async function verify_issue_delete_access(
  issue_id: string,
  project_id: string,
  user: LabUser,
) {
  const issue = find_issue(issue_id, project_id);
  if (!issue) {
    return deny();
  }
  // owner_id_filter: creator may destroy
  if (is_creator(issue, user)) {
    return issue;
  }
  if (!has_project_membership(issue, user)) {
    return deny();
  }
  if (!user.has_project_admin) {
    return deny();
  }
  return issue;
}

// models IssueViewSet.retrieve
async function get_local_plane_issue(req: Request, res: Response) {
  const user = current_user(req);
  const issue = await verify_issue_read_access(
    req.params.id,
    req.params.project_id,
    user,
  );
  return send_file(issue.id);
}

// models IssueViewSet.partial_update
async function update_local_plane_issue(req: Request, res: Response) {
  const user = current_user(req);
  const issue = await verify_issue_update_access(
    req.params.id,
    req.params.project_id,
    user,
  );
  return update(issue.id, { title: "lab-updated" });
}

// models IssueViewSet.destroy
async function delete_local_plane_issue(req: Request, res: Response) {
  const user = current_user(req);
  const issue = await verify_issue_delete_access(
    req.params.id,
    req.params.project_id,
    user,
  );
  return delete_file(issue.id);
}