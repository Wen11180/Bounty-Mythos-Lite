import { Router } from "express";

const router = Router();

router.get("/local/roles/g5k4/:record_id", change_role);

async function change_role(req: Request, res: Response) {
  await verify_role_access(req.params.record_id, req.user);
  return update_role(req.params.record_id);
}

async function verify_role_access(record_id: string, user: User) {
  const record = await load_record(record_id);
  if (user.role !== "reviewer") {
    return deny();
  }
  return record;
}
