import { Router } from "express";

// Local modeling excerpt derived from public mealie-recipes/mealie v3.20.1 sources:
// - mealie/routes/users/crud.py (PUT /users/{item_id} update_user)
// - mealie/routes/users/_helpers.py (assert_user_change_allowed / permission_attrs)
// - mealie/schema/user/user.py (UserBase privilege fields: admin, can_*, group, household)
// Faithful simplified model of self-update mass-assignment defense:
//   1. Client may send UserBase including privilege fields
//   2. assert_user_change_allowed rejects privilege_attr deltas for self and non-self
//   3. Non-admin cannot edit other users or change group/household
//   4. Admin self-edit also cannot change own permission_attrs
// Fail closed: deny() when guard rejects.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type LabUser = {
  id: string;
  admin: boolean;
  group: string;
  household: string;
  can_invite: boolean;
  can_manage: boolean;
  can_manage_household: boolean;
  can_organize: boolean;
};

type UserBase = {
  admin: boolean;
  group: string;
  household: string;
  can_invite: boolean;
  can_manage: boolean;
  can_manage_household: boolean;
  can_organize: boolean;
  full_name?: string;
};

const permission_attrs = [
  "can_invite",
  "can_manage",
  "can_manage_household",
  "can_organize",
  "admin",
] as const;

const router = Router();

router.put(
  "/local/mealie/api/users/self-update",
  update_local_mealie_self_user,
);
router.put(
  "/local/mealie/api/users/admin-self-guard",
  update_local_mealie_admin_self,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    admin: Boolean((req as any).user?.admin || false),
    group: String((req as any).user?.group || "group-lab-1"),
    household: String((req as any).user?.household || "house-lab-1"),
    can_invite: false,
    can_manage: false,
    can_manage_household: false,
    can_organize: false,
  };
}

// models permission_attrs privilege delta check
function forbid_privilege_fields(current: LabUser, new_data: UserBase): boolean {
  for (const p of permission_attrs) {
    if ((current as any)[p] !== (new_data as any)[p]) {
      return false;
    }
  }
  return true;
}

// models assert_user_change_allowed from routes/users/_helpers.py
function assert_user_change_allowed(
  user_id: string,
  current_user: LabUser,
  new_data: UserBase,
) {
  if (!current_user.admin) {
    if (current_user.id !== user_id) {
      return deny();
    }
    if (!forbid_privilege_fields(current_user, new_data)) {
      return deny();
    }
    if (current_user.group !== new_data.group) {
      return deny();
    }
    if (current_user.household !== new_data.household) {
      return deny();
    }
    return true;
  }
  // admin path: must edit self via this route; still block own permission_attrs
  if (current_user.id !== user_id) {
    return deny();
  }
  if (!forbid_privilege_fields(current_user, new_data)) {
    return deny();
  }
  return true;
}

// models prepare path: mass-assignment guard before persist
function prepare_user_update(
  user_id: string,
  current: LabUser,
  new_data: UserBase,
) {
  const ok = assert_user_change_allowed(user_id, current, new_data);
  if (!ok) {
    return deny();
  }
  return new_data;
}

// models repos.users.update(item_id, new_data.model_dump())
function update_user(user_id: string, new_data: UserBase) {
  return { id: user_id, ...new_data };
}

// models PUT /users/{item_id} non-admin self update
async function update_local_mealie_self_user(req: Request, res: Response) {
  const user = current_user(req);
  const item_id = String((req as any).params?.item_id || user.id);
  const new_data = (req as any).body as UserBase;
  const safe = prepare_user_update(item_id, user, new_data);
  return update_user(item_id, safe);
}

// models admin self-edit still blocked on permission_attrs
async function update_local_mealie_admin_self(req: Request, res: Response) {
  const user = {
    ...current_user(req),
    admin: true,
  };
  const item_id = String((req as any).params?.item_id || user.id);
  const new_data = (req as any).body as UserBase;
  const safe = prepare_user_update(item_id, user, new_data);
  return update_user(item_id, safe);
}