import { Router } from "express";

// Teaching reverse-calibration package (intentionally unguarded).
// Models user self-update with client-controlled privilege fields and no
// assert_user_change_allowed / forbid_privilege_fields guard before update_user.
// Complements refute package my-gh-mealie-mass (assert_user_change_allowed).
// Local static review only. Not a public target. Not a bounty submission.

type LabUser = {
  id: string;
  admin: boolean;
};

type UserBase = {
  admin?: boolean;
  can_manage?: boolean;
  full_name?: string;
};

const router = Router();

router.put("/local/lab/users/self-update", update_local_lab_self_user);
router.put("/local/lab/users/profile-update", update_local_lab_profile);

function current_user(req: Request): LabUser {
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    admin: Boolean((req as any).user?.admin || false),
  };
}

// models repos.users.update without mass-assignment guard
function update_user(user_id: string, new_data: UserBase) {
  return { id: user_id, ...new_data };
}

// intentionally unguarded: body privilege fields reach update_user
async function update_local_lab_self_user(req: Request, res: Response) {
  const user = current_user(req);
  const item_id = String((req as any).params?.item_id || user.id);
  const new_data = (req as any).body as UserBase;
  return update_user(item_id, new_data);
}

async function update_local_lab_profile(req: Request, res: Response) {
  const user = current_user(req);
  const new_data = (req as any).body as UserBase;
  return update_user(user.id, new_data);
}
