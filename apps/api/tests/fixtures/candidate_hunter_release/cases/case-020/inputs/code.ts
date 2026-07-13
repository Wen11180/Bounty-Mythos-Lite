import { Router } from "express";

const router = Router();

router.get("/local/roles/l7v6/:record_id", change_role);

async function change_role(req: Request, res: Response) {
  const record = await load_public_role_change(req.params.record_id);
  return update_role(record.path);
}

async function load_public_role_change(record_id: string) {
  return record_store.get(record_id, { visibility: "public" });
}