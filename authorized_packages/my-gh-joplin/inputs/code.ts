import { Router } from "express";

// Local modeling excerpt derived from public laurent22/joplin packages/server v3.7.1:
// - models/ItemModel.ts loadByName(s) via user_items.user_id + checkIfAllowed
// - models/ShareModel.ts owner_id gate
// - routes/api/items.ts get/delete paths
// Faithful simplified model:
//   - Item visibility: user_items membership (group_id) OR owner_id
//   - Delete on shared item: share owner OR accepted share participant residual
//   - Share get: owner_id only
// Fail closed: deny() when membership/owner checks fail.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type ItemRecord = {
  id: string;
  // models items.owner_id
  owner_id: string;
  // models user_items linkage / share membership scope for the session user
  group_id: string;
  // models jop_share_id presence
  shared: boolean;
  title: string;
};

type ShareRecord = {
  id: string;
  // models shares.owner_id
  owner_id: string;
  item_id: string;
};

type LabUser = {
  id: string;
  // models user_items.user_id / share participant scope
  group_id: string;
  // models accepted ShareUserStatus for shared item mutations
  share_accepted: boolean;
};

const router = Router();

router.get(
  "/local/joplin/api/items/:id",
  get_local_joplin_item,
);
router.delete(
  "/local/joplin/api/items/:id",
  delete_local_joplin_item,
);
router.get(
  "/local/joplin/api/shares/:id",
  get_local_joplin_share,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    group_id: String((req as any).user?.group_id || "user-lab-2"),
    share_accepted: Boolean((req as any).user?.share_accepted ?? false),
  };
}

// models item loadByName via user_items join
function find_item(item_id: string): ItemRecord | null {
  if (!item_id) {
    return null;
  }
  return {
    id: item_id,
    owner_id: "owner-lab-1",
    // group_id models the owner/participant user_items.user_id bucket for this item
    group_id: "owner-lab-1",
    shared: true,
    title: "lab-note",
  };
}

function find_share(share_id: string): ShareRecord | null {
  if (!share_id) {
    return null;
  }
  return {
    id: share_id,
    owner_id: "owner-lab-1",
    item_id: "item-lab-1",
  };
}

// models items.owner_id === user.id
function is_item_owner(item: ItemRecord, user: LabUser): boolean {
  // owner_id_filter
  return item.owner_id === user.id;
}

// models user_items.user_id membership used by loadByNames
function has_user_item_membership(item: ItemRecord, user: LabUser): boolean {
  // group_id_filter: only items linked to this user are visible
  return item.group_id === user.group_id || item.group_id === user.id;
}

// models checkIfAllowed Delete/Update on shared item: share owner or accepted shareUser
function may_mutate_shared_item(item: ItemRecord, user: LabUser): boolean {
  if (!item.shared) {
    return is_item_owner(item, user) || has_user_item_membership(item, user);
  }
  if (is_item_owner(item, user)) {
    return true;
  }
  // accepted share participant residual
  return has_user_item_membership(item, user) && user.share_accepted;
}

// models loadByName scoped then return item
async function verify_item_read_access(item_id: string, user: LabUser) {
  const item = find_item(item_id);
  if (!item) {
    return deny();
  }
  // owner short-circuit
  if (is_item_owner(item, user)) {
    return item;
  }
  // user_items membership required for non-owners
  if (!has_user_item_membership(item, user)) {
    return deny();
  }
  return item;
}

// models delItems: loadByName + checkIfAllowed(Delete)
async function verify_item_delete_access(item_id: string, user: LabUser) {
  const item = find_item(item_id);
  if (!item) {
    return deny();
  }
  if (!may_mutate_shared_item(item, user)) {
    return deny();
  }
  return item;
}

// models ShareModel checkIfAllowed: user.id === share.owner_id
async function verify_share_read_access(share_id: string, user: LabUser) {
  const share = find_share(share_id);
  if (!share) {
    return deny();
  }
  // owner_id_filter
  if (share.owner_id !== user.id) {
    return deny();
  }
  return share;
}

async function get_local_joplin_item(req: Request, res: Response) {
  const user = current_user(req);
  const item = await verify_item_read_access(req.params.id, user);
  return send_file(item.id);
}

async function delete_local_joplin_item(req: Request, res: Response) {
  const user = current_user(req);
  const item = await verify_item_delete_access(req.params.id, user);
  return delete_file(item.id);
}

async function get_local_joplin_share(req: Request, res: Response) {
  const user = current_user(req);
  const share = await verify_share_read_access(req.params.id, user);
  return send_file(share.id);
}