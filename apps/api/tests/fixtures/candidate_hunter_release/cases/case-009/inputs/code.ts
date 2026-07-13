import { Router } from "express";

const router = Router();

router.get("/local/archives/t2b5/:record_id", export_archive);

async function export_archive(req: Request, res: Response) {
  return export(req.params.record_id);
}