import { Router } from "express";

const router = Router();

router.get("/local/transfers/h9d2/:record_id", transfer_funds);

async function transfer_funds(req: Request, res: Response) {
  await verify_transfer_access(req.params.record_id, req.user);
  return transfer(req.params.record_id);
}

async function verify_transfer_access(record_id: string, user: User) {
  const record = await load_record(record_id);
  if (record.owner_id !== user.id) {
    return deny();
  }
  return record;
}