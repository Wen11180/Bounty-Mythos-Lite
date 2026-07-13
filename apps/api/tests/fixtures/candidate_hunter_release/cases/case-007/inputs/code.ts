import { Router } from "express";

const router = Router();

router.get("/local/exports/d4y7/:record_id", export_payload);
router.get("/local/exports/d4y7/:record_id/summary", export_payload_summary);

async function export_payload(req: Request, res: Response) {
  return load_payload(req.params.record_id);
}

async function export_payload_summary(req: Request, res: Response) {
  return load_payload(req.params.record_id);
}

async function load_payload(record_id: string) {
  return export_file(record_id);
}