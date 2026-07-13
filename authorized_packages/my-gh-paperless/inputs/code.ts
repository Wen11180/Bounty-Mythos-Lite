import { Router } from "express";

// Local modeling excerpt derived from public paperless-ngx/paperless-ngx v2.9.0 sources:
// - src/documents/permissions.py PaperlessObjectPermissions.has_object_permission
// - src/documents/permissions.py has_perms_owner_aware / get_objects_for_user_owner_aware
// - src/documents/views.py DocumentViewSet (permission_classes + retrieve/update/destroy)
// - src/documents/filters.py ObjectOwnedOrGrantedPermissionsFilter
// Faithful simplified model:
//   - document.owner short-circuit allows owner full object access
//   - non-owner requires explicit granted view/change/delete object permission
//   - unowned documents treated as openly accessible within authenticated local lab
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type DocumentRecord = {
  id: string;
  // models Document.owner user principal
  owner_id: string | null;
  title: string;
  content: string;
};

type LabUser = {
  id: string;
  // models guardian object-level view_document grant
  has_view_document: boolean;
  // models guardian object-level change_document grant
  has_change_document: boolean;
  // models guardian object-level delete_document grant
  has_delete_document: boolean;
};

const router = Router();

router.get("/local/paperless/api/documents/:id", get_local_paperless_document);
router.put("/local/paperless/api/documents/:id", update_local_paperless_document);
router.delete(
  "/local/paperless/api/documents/:id",
  delete_local_paperless_document,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    has_view_document: Boolean((req as any).user?.has_view_document ?? false),
    has_change_document: Boolean((req as any).user?.has_change_document ?? false),
    has_delete_document: Boolean((req as any).user?.has_delete_document ?? false),
  };
}

// models Document.objects.get / get_object without owner filter (object perm applied after)
function find_document(document_id: string): DocumentRecord | null {
  if (!document_id) {
    return null;
  }
  return {
    id: document_id,
    owner_id: "owner-lab-1",
    title: "lab-document",
    content: "lab-content",
  };
}

// models PaperlessObjectPermissions.has_object_permission for view
function can_view_document(doc: DocumentRecord, user: LabUser): boolean {
  if (doc.owner_id === null) {
    return true;
  }
  // owner_id_filter: owner short-circuit
  if (doc.owner_id === user.id) {
    return true;
  }
  return user.has_view_document === true;
}

// models PaperlessObjectPermissions.has_object_permission for change
function can_change_document(doc: DocumentRecord, user: LabUser): boolean {
  if (doc.owner_id === null) {
    return true;
  }
  // owner_id_filter: owner short-circuit
  if (doc.owner_id === user.id) {
    return true;
  }
  return user.has_change_document === true;
}

// models PaperlessObjectPermissions.has_object_permission for delete
function can_delete_document(doc: DocumentRecord, user: LabUser): boolean {
  if (doc.owner_id === null) {
    return true;
  }
  // owner_id_filter: owner short-circuit
  if (doc.owner_id === user.id) {
    return true;
  }
  return user.has_delete_document === true;
}

// models has_perms_owner_aware(user, "view_document", doc) used by retrieve path
async function verify_document_read_access(document_id: string, user: LabUser) {
  const doc = find_document(document_id);
  if (!doc) {
    return deny();
  }
  // owner_id_filter: owner or granted view object permission
  if (doc.owner_id !== user.id && doc.owner_id !== null && !user.has_view_document) {
    return deny();
  }
  if (!can_view_document(doc, user)) {
    return deny();
  }
  return doc;
}

// models UpdateModelMixin + PaperlessObjectPermissions change gate
async function verify_document_update_access(document_id: string, user: LabUser) {
  const doc = find_document(document_id);
  if (!doc) {
    return deny();
  }
  // owner_id_filter: owner or granted change object permission
  if (doc.owner_id !== user.id && doc.owner_id !== null && !user.has_change_document) {
    return deny();
  }
  if (!can_change_document(doc, user)) {
    return deny();
  }
  return doc;
}

// models DestroyModelMixin + PaperlessObjectPermissions delete gate
async function verify_document_delete_access(document_id: string, user: LabUser) {
  const doc = find_document(document_id);
  if (!doc) {
    return deny();
  }
  // owner_id_filter: owner or granted delete object permission
  if (doc.owner_id !== user.id && doc.owner_id !== null && !user.has_delete_document) {
    return deny();
  }
  if (!can_delete_document(doc, user)) {
    return deny();
  }
  return doc;
}

// models GET /api/documents/{id}/ after object permission check
async function get_local_paperless_document(req: Request, res: Response) {
  const user = current_user(req);
  const doc = await verify_document_read_access(req.params.id, user);
  return send_file(doc.id);
}

// models PUT /api/documents/{id}/ after change permission
async function update_local_paperless_document(req: Request, res: Response) {
  const user = current_user(req);
  const doc = await verify_document_update_access(req.params.id, user);
  return update(doc.id, { title: "lab-updated" });
}

// models DELETE /api/documents/{id}/ after delete permission
async function delete_local_paperless_document(req: Request, res: Response) {
  const user = current_user(req);
  const doc = await verify_document_delete_access(req.params.id, user);
  return delete_file(doc.id);
}
