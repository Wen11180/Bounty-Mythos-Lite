import { Router } from "express";

const router = Router();

router.get("/local/transfers/y3m7/:record_id", transfer_funds);

async function transfer_funds(req: Request, res: Response) {
  const record = await load_public_transfer(req.params.record_id);
  return transfer(record.path);
}

async function load_public_transfer(record_id: string) {
  return record_store.get(record_id, { visibility: "public" });
}