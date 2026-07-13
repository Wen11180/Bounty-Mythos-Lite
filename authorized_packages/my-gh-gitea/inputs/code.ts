import { Router } from "express";

// Local modeling excerpt derived from public go-gitea/gitea sources:
// - routers/api/v1/repo/issue.go GetIssue
// - models/perm/access/repo_permission.go CanReadIssuesOrPulls / CanRead
// - issue load: GetIssueWithAttrsByIndex(ctx, repository.ID, index)
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type RepoRecord = {
  id: string;
  owner_id: string;
  visibility: "private" | "public";
  issues_unit_enabled: boolean;
};

type IssueRecord = {
  repo_id: string;
  index: string;
  is_pull: boolean;
  title: string;
};

type LabUser = {
  id: string;
  // models unit access derived from membership / public visibility
  can_read_issues_on_repo: boolean;
  can_read_pulls_on_repo: boolean;
};

const router = Router();

router.get(
  "/local/gitea/api/v1/repos/:owner/:repo/issues/:index",
  get_local_gitea_issue,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    can_read_issues_on_repo: Boolean(
      (req as any).user?.can_read_issues_on_repo ?? false,
    ),
    can_read_pulls_on_repo: Boolean(
      (req as any).user?.can_read_pulls_on_repo ?? false,
    ),
  };
}

// models repository resolution in API context (owner/repo path)
function find_repo(owner: string, repo: string): RepoRecord | null {
  if (!owner || !repo) {
    return null;
  }
  return {
    id: "repo-lab-1",
    owner_id: "owner-lab-1",
    visibility: "private",
    issues_unit_enabled: true,
  };
}

// models GetIssueWithAttrsByIndex(ctx, repoID, index): always repository-scoped
function get_issue_with_attrs_by_index(
  repo_id: string,
  index: string,
): IssueRecord | null {
  if (!repo_id || !index) {
    return null;
  }
  return {
    repo_id,
    index,
    is_pull: false,
    title: "lab-issue",
  };
}

// models Permission.CanReadIssuesOrPulls(isPull) / unit AccessModeRead
function can_read_issues_or_pulls(user: LabUser, is_pull: boolean): boolean {
  if (is_pull) {
    return user.can_read_pulls_on_repo === true;
  }
  return user.can_read_issues_on_repo === true;
}

// models GetIssue authorization boundary before sensitive sink:
// 1) resolve private repo membership/ownership
// 2) load issue only under that repository.ID
// 3) unit permission CanReadIssuesOrPulls
async function verify_issue_read_access(
  owner: string,
  repo_name: string,
  index: string,
  user: LabUser,
) {
  const repo = find_repo(owner, repo_name);
  if (!repo) {
    return deny();
  }
  // private repository requires ownership/membership before unit read
  if (repo.visibility !== "public" && repo.owner_id !== user.id) {
    // membership may also grant unit read; model explicit unit flags as membership result
    if (!can_read_issues_or_pulls(user, false) && !can_read_issues_or_pulls(user, true)) {
      return deny();
    }
  }
  const issue = get_issue_with_attrs_by_index(repo.id, index);
  if (!issue) {
    return deny();
  }
  // ownership/scope boundary: issue must belong to the resolved repository id
  if (issue.repo_id !== repo.id) {
    return deny();
  }
  // unit permission gate before JSON/body sink
  if (!can_read_issues_or_pulls(user, issue.is_pull)) {
    return deny();
  }
  return issue;
}

// models GET /repos/{owner}/{repo}/issues/{index}
async function get_local_gitea_issue(req: Request, res: Response) {
  const user = current_user(req);
  const issue = await verify_issue_read_access(
    req.params.owner,
    req.params.repo,
    req.params.index,
    user,
  );
  return send_file(issue.index);
}
