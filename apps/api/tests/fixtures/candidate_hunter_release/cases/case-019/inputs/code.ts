import { Router } from "express";

const router = Router();

router.get("/local/roles/z2r9/:record_id", change_role);
router.get("/local/roles/z2r9/:record_id/summary", change_role_summary);

async function change_role(req: Request, res: Response) {
  return load_role_change(req.params.record_id);
}

async function change_role_summary(req: Request, res: Response) {
  return load_role_change(req.params.record_id);
}

async function load_role_change(record_id: string) {
  return update_role(record_id);
}