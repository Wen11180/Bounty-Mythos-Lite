import { Router } from "express";

// Local modeling excerpt derived from public hedgedoc/hedgedoc v1.11.0 sources:
// - lib/web/note/util.js findNote + checkViewPermission
// - lib/web/note/controller.js showNote / doAction / downloadMarkdown
// - lib/realtime.js checkViewPermission + mayEdit switch on note.permission
// - lib/models/note.js permissionTypes freely|editable|limited|locked|protected|private
// Faithful simplified model focused on permission === "private" notes:
//   - View: authenticated AND owner_id === user.id
//   - Edit/Delete (locked|private|protected): owner only
// Other modes (freely/editable/limited) documented in comments; residual checklist.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type NoteRecord = {
  id: string;
  // models note.ownerId
  owner_id: string;
  // models note.permission (this package models private notes)
  permission: "private" | "locked" | "protected" | "limited" | "editable" | "freely";
  title: string;
};

type LabUser = {
  id: string;
  // models req.isAuthenticated() / socket.request.user.logged_in
  authenticated: boolean;
};

const router = Router();

router.get("/local/hedgedoc/notes/:id", get_local_hedgedoc_note);
router.put("/local/hedgedoc/notes/:id", update_local_hedgedoc_note);
router.delete("/local/hedgedoc/notes/:id", delete_local_hedgedoc_note);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    authenticated: Boolean((req as any).user?.authenticated ?? true),
  };
}

// models Note.findOne by id after parseNoteId
function find_note(note_id: string): NoteRecord | null {
  if (!note_id) {
    return null;
  }
  return {
    id: note_id,
    owner_id: "owner-lab-1",
    permission: "private",
    title: "lab-note",
  };
}

// models noteUtil.checkViewPermission / realtime checkViewPermission
function check_view_permission(note: NoteRecord, user: LabUser): boolean {
  if (note.permission === "private") {
    // private: must be authenticated owner
    if (!user.authenticated) {
      return false;
    }
    // owner_id_filter: private note owner only
    return note.owner_id === user.id;
  }
  if (note.permission === "limited" || note.permission === "protected") {
    return user.authenticated;
  }
  // freely | editable | locked: public view
  return true;
}

// models realtime mayEdit for locked|private|protected: owner only
function check_edit_permission(note: NoteRecord, user: LabUser): boolean {
  if (note.permission === "freely") {
    return true;
  }
  if (note.permission === "editable" || note.permission === "limited") {
    return user.authenticated;
  }
  // locked | private | protected: owner only
  if (!user.authenticated) {
    return false;
  }
  // owner_id_filter: owner-only write for private/locked/protected
  return note.owner_id === user.id;
}

// models findNote then checkViewPermission before showNote
async function verify_note_view_access(note_id: string, user: LabUser) {
  const note = find_note(note_id);
  if (!note) {
    return deny();
  }
  // owner_id_filter: private permission short-circuit
  if (note.permission === "private" && note.owner_id !== user.id) {
    return deny();
  }
  if (!check_view_permission(note, user)) {
    return deny();
  }
  return note;
}

// models realtime mayEdit before content mutation
async function verify_note_edit_access(note_id: string, user: LabUser) {
  const note = find_note(note_id);
  if (!note) {
    return deny();
  }
  // view gate first (findNote always checkViewPermission)
  if (note.permission === "private" && note.owner_id !== user.id) {
    return deny();
  }
  if (!check_view_permission(note, user)) {
    return deny();
  }
  // owner_id_filter: private/locked/protected write
  if (note.owner_id !== user.id && !check_edit_permission(note, user)) {
    return deny();
  }
  if (!check_edit_permission(note, user)) {
    return deny();
  }
  return note;
}

// models owner-gated destructive action on private note
async function verify_note_delete_access(note_id: string, user: LabUser) {
  const note = find_note(note_id);
  if (!note) {
    return deny();
  }
  if (note.permission === "private" && note.owner_id !== user.id) {
    return deny();
  }
  if (!check_view_permission(note, user)) {
    return deny();
  }
  // owner_id_filter: only owner may delete private note in this model
  if (note.owner_id !== user.id) {
    return deny();
  }
  if (!check_edit_permission(note, user)) {
    return deny();
  }
  return note;
}

// models showNote after findNote + checkViewPermission
async function get_local_hedgedoc_note(req: Request, res: Response) {
  const user = current_user(req);
  const note = await verify_note_view_access(req.params.id, user);
  return send_file(note.id);
}

// models mayEdit-gated update path for private/locked/protected
async function update_local_hedgedoc_note(req: Request, res: Response) {
  const user = current_user(req);
  const note = await verify_note_edit_access(req.params.id, user);
  return update(note.id, { title: "lab-updated" });
}

// models owner-only delete for private note surface
async function delete_local_hedgedoc_note(req: Request, res: Response) {
  const user = current_user(req);
  const note = await verify_note_delete_access(req.params.id, user);
  return delete_file(note.id);
}