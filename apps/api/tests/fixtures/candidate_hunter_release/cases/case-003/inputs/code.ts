import { Router } from "express";

const router = Router();

router.get("/local/records/n8v3/:record_id", read_record);
router.get("/local/records/n8v3/:record_id/summary", read_record_summary);

async function read_record(req: Request, res: Response) {
  return load_record(req.params.record_id);
}

async function read_record_summary(req: Request, res: Response) {
  return load_record(req.params.record_id);
}

async function load_record(record_id: string) {
  return send_file(record_id);
}