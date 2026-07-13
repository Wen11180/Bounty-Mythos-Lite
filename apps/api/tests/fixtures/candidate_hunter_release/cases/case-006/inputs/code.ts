import { Router } from "express";

const router = Router();

router.get("/local/exports/j9p2/:record_id", export_payload);

async function export_payload(req: Request, res: Response) {
  await verify_payload_access(req.params.record_id, req.user);
  return export_file(req.params.record_id);
}

async function verify_payload_access(record_id: string, user: User) {
  const record = await load_record(record_id);
  if (user.role !== "reviewer") {
    return deny();
  }
  return record;
}
