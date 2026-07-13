import { Router } from "express";

const router = Router();

router.get("/local/archives/r7f3/:record_id", export_archive);

async function export_archive(req: Request, res: Response) {
  const record = await load_public_archive(req.params.record_id);
  return export(record.path);
}

async function load_public_archive(record_id: string) {
  return record_store.get(record_id, { visibility: "public" });
}