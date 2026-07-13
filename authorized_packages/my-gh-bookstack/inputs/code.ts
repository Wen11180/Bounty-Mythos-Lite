import { Router } from "express";

// Local modeling excerpt derived from public BookStackApp/BookStack v26.05.2 sources:
// - app/Entities/Controllers/PageApiController.php read/update/delete
// - app/Entities/Queries/PageQueries.php findVisibleByIdOrFail
// - app/Entities/Models/Page.php scopeVisible (+ draft restrict)
// - app/Permissions/PermissionApplicator.php restrictEntityQuery / checkOwnableUserAccess
// - app/Http/Controller.php checkOwnablePermission
// Faithful simplified model: visibility load + ownable owner_id boundary before sinks.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type PageRecord = {
  id: string;
  owner_id: string; // models owned_by
  draft: boolean;
  created_by: string;
  html: string;
};

type LabUser = {
  id: string;
  // models role permission page-update-all / page-delete-all
  is_admin: boolean;
  // models joint-permission visibility for current roles (view)
  can_view_page: boolean;
};

const router = Router();

router.get("/local/bookstack/api/pages/:id", get_local_bookstack_page);
router.put("/local/bookstack/api/pages/:id", update_local_bookstack_page);
router.delete("/local/bookstack/api/pages/:id", delete_local_bookstack_page);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    is_admin: Boolean((req as any).user?.is_admin ?? false),
    can_view_page: Boolean((req as any).user?.can_view_page ?? false),
  };
}

// models Page::query()->find without visibility (internal only)
function find_page(page_id: string): PageRecord | null {
  if (!page_id) {
    return null;
  }
  return {
    id: page_id,
    owner_id: "owner-lab-1",
    draft: false,
    created_by: "owner-lab-1",
    html: "lab-page-body",
  };
}

// models PageQueries.findVisibleByIdOrFail:
// scopes('visible') -> PermissionApplicator.restrictEntityQuery + draft restrict
function find_visible_page_by_id(page_id: string, user: LabUser): PageRecord | null {
  const page = find_page(page_id);
  if (!page) {
    return null;
  }
  // draft pages only for creator
  if (page.draft && page.created_by !== user.id) {
    return null;
  }
  // joint permission visibility OR owner
  if (!user.can_view_page && page.owner_id !== user.id) {
    return null; // NotFoundException fail-closed
  }
  return page;
}

// models checkOwnablePermission(PageUpdate/PageDelete, page)
// PermissionApplicator: all-role OR (owner && own-role)
async function verify_page_read_access(page_id: string, user: LabUser) {
  const page = find_visible_page_by_id(page_id, user);
  if (!page) {
    return deny();
  }
  // ownership/visibility boundary already applied in find_visible_page_by_id
  if (page.owner_id !== user.id && !user.can_view_page) {
    return deny();
  }
  return page;
}

async function verify_page_update_access(page_id: string, user: LabUser) {
  const page = find_visible_page_by_id(page_id, user);
  if (!page) {
    return deny();
  }
  // owner_id_filter: PageUpdate ownable boundary before update sink
  if (page.owner_id !== user.id && !user.is_admin) {
    return deny();
  }
  return page;
}

async function verify_page_delete_access(page_id: string, user: LabUser) {
  const page = find_visible_page_by_id(page_id, user);
  if (!page) {
    return deny();
  }
  // owner_id_filter: PageDelete ownable boundary before delete sink
  if (page.owner_id !== user.id && !user.is_admin) {
    return deny();
  }
  return page;
}

// models GET /api/pages/{id}
async function get_local_bookstack_page(req: Request, res: Response) {
  const user = current_user(req);
  const page = await verify_page_read_access(req.params.id, user);
  return send_file(page.id);
}

// models PUT /api/pages/{id}
async function update_local_bookstack_page(req: Request, res: Response) {
  const user = current_user(req);
  const page = await verify_page_update_access(req.params.id, user);
  return update(page.id, { html: "lab-updated" });
}

// models DELETE /api/pages/{id}
async function delete_local_bookstack_page(req: Request, res: Response) {
  const user = current_user(req);
  const page = await verify_page_delete_access(req.params.id, user);
  return delete_file(page.id);
}