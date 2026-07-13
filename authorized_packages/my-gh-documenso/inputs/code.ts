import { Router } from "express";

// Local modeling excerpt derived from public documenso/documenso v2.14.0 sources:
// - packages/lib/server-only/envelope/get-envelope-by-id.ts getEnvelopeWhereInput
// - packages/lib/server-only/document/delete-document.ts hasDeleteAccess
// - packages/lib/server-only/envelope/update-envelope.ts (loads via getEnvelopeById)
// - packages/trpc/server/document-router get/update/delete authenticatedProcedure
// - packages/lib/constants/teams.ts TEAM_DOCUMENT_VISIBILITY_MAP
// Faithful simplified model:
//   - Document owner: owner_id === user.id
//   - Team scope: group_id (teamId) membership required for team-visibility path
//   - Team role visibility map simplified as has_team_visibility
//   - Fail closed: deny() when neither owner nor (team membership + visibility)
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type DocumentRecord = {
  id: string;
  // models envelope.userId (document owner)
  owner_id: string;
  // models envelope.teamId
  group_id: string;
  // models envelope.visibility simplified to EVERYONE for team path
  team_visible: boolean;
  title: string;
};

type LabUser = {
  id: string;
  // models validated team membership (getTeamById for userId+teamId)
  group_id: string;
  // models TEAM_DOCUMENT_VISIBILITY_MAP[currentTeamRole] contains visibility
  has_team_visibility: boolean;
};

const router = Router();

router.get("/local/documenso/api/documents/:id", get_local_documenso_document);
router.put("/local/documenso/api/documents/:id", update_local_documenso_document);
router.delete("/local/documenso/api/documents/:id", delete_local_documenso_document);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    group_id: String((req as any).user?.group_id || "team-lab-2"),
    has_team_visibility: Boolean((req as any).user?.has_team_visibility ?? false),
  };
}

// models prisma.envelope find by document id
function find_document(document_id: string): DocumentRecord | null {
  if (!document_id) {
    return null;
  }
  return {
    id: document_id,
    owner_id: "owner-lab-1",
    group_id: "team-lab-1",
    team_visible: true,
    title: "lab-document",
  };
}

// models getEnvelopeWhereInput OR branches:
// owner userId OR (teamId + visibility map) — team email path residual
function can_access_document(doc: DocumentRecord, user: LabUser): boolean {
  // owner_id_filter: document owner short-circuit
  if (doc.owner_id === user.id) {
    return true;
  }
  // group_id_filter: team membership + role visibility
  if (doc.group_id === user.group_id && user.has_team_visibility && doc.team_visible) {
    return true;
  }
  return false;
}

// models getEnvelopeById / getDocumentWithDetailsById
async function verify_document_read_access(document_id: string, user: LabUser) {
  const doc = find_document(document_id);
  if (!doc) {
    return deny();
  }
  // owner_id_filter before team path
  if (doc.owner_id !== user.id && !can_access_document(doc, user)) {
    return deny();
  }
  // group_id_filter: non-owner must match team
  if (doc.owner_id !== user.id && doc.group_id !== user.group_id) {
    return deny();
  }
  if (!can_access_document(doc, user)) {
    return deny();
  }
  return doc;
}

// models updateEnvelope after getEnvelopeById access
async function verify_document_update_access(document_id: string, user: LabUser) {
  const doc = find_document(document_id);
  if (!doc) {
    return deny();
  }
  if (doc.owner_id !== user.id && !can_access_document(doc, user)) {
    return deny();
  }
  if (doc.owner_id !== user.id && doc.group_id !== user.group_id) {
    return deny();
  }
  if (!can_access_document(doc, user)) {
    return deny();
  }
  return doc;
}

// models deleteDocument hasDeleteAccess via getEnvelopeWhereInput
async function verify_document_delete_access(document_id: string, user: LabUser) {
  const doc = find_document(document_id);
  if (!doc) {
    return deny();
  }
  // owner_id_filter / group_id_filter same as hasDeleteAccess
  if (doc.owner_id !== user.id && !can_access_document(doc, user)) {
    return deny();
  }
  if (doc.owner_id !== user.id && doc.group_id !== user.group_id) {
    return deny();
  }
  if (!can_access_document(doc, user)) {
    return deny();
  }
  return doc;
}

// models document.get authenticatedProcedure
async function get_local_documenso_document(req: Request, res: Response) {
  const user = current_user(req);
  const doc = await verify_document_read_access(req.params.id, user);
  return send_file(doc.id);
}

// models document.update authenticatedProcedure
async function update_local_documenso_document(req: Request, res: Response) {
  const user = current_user(req);
  const doc = await verify_document_update_access(req.params.id, user);
  return update(doc.id, { title: "lab-updated" });
}

// models document.delete authenticatedProcedure
async function delete_local_documenso_document(req: Request, res: Response) {
  const user = current_user(req);
  const doc = await verify_document_delete_access(req.params.id, user);
  return delete_file(doc.id);
}