import { Router } from "express";

const router = Router();

router.get("/local/archives/v1n9/:record_id", export_archive);
router.get("/local/archives/v1n9/:record_id/summary", export_archive_summary);

async function export_archive(req: Request, res: Response) {
  return load_archive(req.params.record_id);
}

async function export_archive_summary(req: Request, res: Response) {
  return load_archive(req.params.record_id);
}

async function load_archive(record_id: string) {
  return export(record_id);
}