import { Router } from "express";

const router = Router();

router.get("/local/records/x2k9/:record_id", read_record);

async function read_record(req: Request, res: Response) {
  await verify_record_access(req.params.record_id, req.user);
  return send_file(req.params.record_id);
}

async function verify_record_access(record_id: string, user: User) {
  const record = await load_record(record_id);
  if (record.owner_id !== user.id) {
    return deny();
  }
  return record;
}