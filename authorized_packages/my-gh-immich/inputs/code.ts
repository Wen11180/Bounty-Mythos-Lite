import { Router } from "express";

// Local modeling excerpt derived from public immich-app/immich v2.7.5 sources:
// - server/src/utils/access.ts requireAccess / checkAccess / checkOtherAccess
// - server/src/repositories/access.repository.ts AssetAccess.checkOwnerAccess
// - server/src/services/asset.service.ts get / update / deleteAll
// Faithful simplified model:
//   - AssetRead: owner OR album membership OR partner share
//   - AssetUpdate / AssetDelete: owner only (checkOwnerAccess)
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type AssetRecord = {
  id: string;
  // models asset.ownerId
  owner_id: string;
  // models album membership share path for read
  album_shared: boolean;
  // models partner share path for read
  partner_shared: boolean;
  title: string;
};

type LabUser = {
  id: string;
  // models album membership for AssetRead non-owner path
  has_album_access: boolean;
  // models partner access for AssetRead non-owner path
  has_partner_access: boolean;
};

const router = Router();

router.get("/local/immich/api/assets/:id", get_local_immich_asset);
router.put("/local/immich/api/assets/:id", update_local_immich_asset);
router.delete("/local/immich/api/assets/:id", delete_local_immich_asset);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    has_album_access: Boolean((req as any).user?.has_album_access ?? false),
    has_partner_access: Boolean((req as any).user?.has_partner_access ?? false),
  };
}

// models asset repository getById
function find_asset(asset_id: string): AssetRecord | null {
  if (!asset_id) {
    return null;
  }
  return {
    id: asset_id,
    owner_id: "owner-lab-1",
    album_shared: false,
    partner_shared: false,
    title: "lab-asset",
  };
}

// models access.asset.checkOwnerAccess
function check_owner_access(asset: AssetRecord, user: LabUser): boolean {
  return asset.owner_id === user.id;
}

// models Permission.AssetRead: owner | album | partner
function can_read_asset(asset: AssetRecord, user: LabUser): boolean {
  if (check_owner_access(asset, user)) {
    return true;
  }
  if (user.has_album_access && asset.album_shared) {
    return true;
  }
  if (user.has_partner_access && asset.partner_shared) {
    return true;
  }
  return false;
}

// models Permission.AssetUpdate / AssetDelete: owner only
function can_write_asset(asset: AssetRecord, user: LabUser): boolean {
  return check_owner_access(asset, user);
}

// models requireAccess({ permission: Permission.AssetRead, ids: [id] })
async function verify_asset_read_access(asset_id: string, user: LabUser) {
  const asset = find_asset(asset_id);
  if (!asset) {
    return deny();
  }
  // owner_id_filter: owner short-circuit before album/partner share paths
  if (asset.owner_id !== user.id && !can_read_asset(asset, user)) {
    return deny();
  }
  if (!can_read_asset(asset, user)) {
    return deny();
  }
  return asset;
}

// models requireAccess({ permission: Permission.AssetUpdate, ids: [id] })
async function verify_asset_update_access(asset_id: string, user: LabUser) {
  const asset = find_asset(asset_id);
  if (!asset) {
    return deny();
  }
  // owner_id_filter: AssetUpdate requires checkOwnerAccess only
  if (asset.owner_id !== user.id) {
    return deny();
  }
  if (!can_write_asset(asset, user)) {
    return deny();
  }
  return asset;
}

// models requireAccess({ permission: Permission.AssetDelete, ids })
async function verify_asset_delete_access(asset_id: string, user: LabUser) {
  const asset = find_asset(asset_id);
  if (!asset) {
    return deny();
  }
  // owner_id_filter: AssetDelete requires checkOwnerAccess only
  if (asset.owner_id !== user.id) {
    return deny();
  }
  if (!can_write_asset(asset, user)) {
    return deny();
  }
  return asset;
}

// models asset.service.get after AssetRead requireAccess
async function get_local_immich_asset(req: Request, res: Response) {
  const user = current_user(req);
  const asset = await verify_asset_read_access(req.params.id, user);
  return send_file(asset.id);
}

// models asset.service.update after AssetUpdate requireAccess
async function update_local_immich_asset(req: Request, res: Response) {
  const user = current_user(req);
  const asset = await verify_asset_update_access(req.params.id, user);
  return update(asset.id, { title: "lab-updated" });
}

// models asset.service.deleteAll after AssetDelete requireAccess
async function delete_local_immich_asset(req: Request, res: Response) {
  const user = current_user(req);
  const asset = await verify_asset_delete_access(req.params.id, user);
  return delete_file(asset.id);
}
