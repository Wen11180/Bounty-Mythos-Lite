import { Router } from "express";

const router = Router();

router.get("/local/roles/b8t1/:record_id", change_role);

async function change_role(req: Request, res: Response) {
  return update_role(req.params.record_id);
}