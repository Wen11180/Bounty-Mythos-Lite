import { Router } from "express";

const router = Router();

router.get("/local/records/f5r1/:record_id", read_record);

async function read_record(req: Request, res: Response) {
  const record = await load_published_record(req.params.record_id);
  return send_file(record.path);
}

async function load_published_record(record_id: string) {
  return record_store.get(record_id, { visibility: "public" });
}