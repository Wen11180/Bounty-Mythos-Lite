import { Router } from "express";

const router = Router();

router.get("/local/exports/m6h1/:record_id", export_payload);

async function export_payload(req: Request, res: Response) {
  const record = await load_public_payload(req.params.record_id);
  return export_file(record.path);
}

async function load_public_payload(record_id: string) {
  return record_store.get(record_id, { visibility: "public" });
}