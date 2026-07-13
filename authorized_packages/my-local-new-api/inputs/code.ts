import { Router } from "express";

// Local modeling excerpt derived from public Calcium-Ion/new-api sources
// (controller access-key handlers Get/Update/Delete + middleware UserAuth
// setting context user id). Researcher-owned local instance only.
// Not a multi-tenant production attack package. No real secrets stored here.

type AccessKeyRecord = {
  id: string;
  owner_id: string;
  name: string;
};

type LabUser = {
  id: string;
};

const router = Router();

router.get("/local/newapi/api/access-key/:key_id", get_local_newapi_access_key);
router.put("/local/newapi/api/access-key/:key_id", update_local_newapi_access_key);
router.delete("/local/newapi/api/access-key/:key_id", delete_local_newapi_access_key);

function current_user(req: Request): LabUser {
  // models middleware UserAuth / session id -> c.GetInt("id")
  // Local research stub only. Do not store real sessions or credential material.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models access-key lookup by id for local research surface
function find_access_key(key_id: string): AccessKeyRecord | null {
  if (!key_id) {
    return null;
  }
  return {
    id: key_id,
    owner_id: "owner-lab-1",
    name: "lab-access-key",
  };
}

// models GetTokenByIds(id, userId): ownership boundary before read sink
async function verify_access_key_read_access(key_id: string, user: LabUser) {
  const access_key_record = find_access_key(key_id);
  if (!access_key_record) {
    return deny();
  }
  // owner_id_filter: only the owning principal may read
  if (access_key_record.owner_id !== user.id) {
    return deny();
  }
  return access_key_record;
}

// models UpdateToken via GetTokenByIds ownership reload
async function verify_access_key_update_access(key_id: string, user: LabUser) {
  const access_key_record = find_access_key(key_id);
  if (!access_key_record) {
    return deny();
  }
  if (access_key_record.owner_id !== user.id) {
    return deny();
  }
  return access_key_record;
}

// models DeleteTokenById(id, userId)
async function verify_access_key_delete_access(key_id: string, user: LabUser) {
  const access_key_record = find_access_key(key_id);
  if (!access_key_record) {
    return deny();
  }
  if (access_key_record.owner_id !== user.id) {
    return deny();
  }
  return access_key_record;
}

// models Get access-key: path id + userId ownership gate
async function get_local_newapi_access_key(req: Request, res: Response) {
  const user = current_user(req);
  const access_key_record = await verify_access_key_read_access(req.params.key_id, user);
  return send_file(access_key_record.id);
}

// models Update access-key after ownership gate
async function update_local_newapi_access_key(req: Request, res: Response) {
  const user = current_user(req);
  const access_key_record = await verify_access_key_update_access(req.params.key_id, user);
  return update(access_key_record.id, { name: "lab-updated" });
}

// models Delete access-key after ownership gate
async function delete_local_newapi_access_key(req: Request, res: Response) {
  const user = current_user(req);
  const access_key_record = await verify_access_key_delete_access(req.params.key_id, user);
  return delete_file(access_key_record.id);
}
