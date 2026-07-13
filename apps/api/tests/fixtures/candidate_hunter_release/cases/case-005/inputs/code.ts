import { Router } from "express";

const router = Router();

router.get("/local/exports/w3c8/:record_id", export_payload);

async function export_payload(req: Request, res: Response) {
  return export_file(req.params.record_id);
}