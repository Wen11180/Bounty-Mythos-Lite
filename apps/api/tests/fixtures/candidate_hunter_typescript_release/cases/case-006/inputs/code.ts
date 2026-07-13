import { Router } from "express";

const router = Router();

router.get("/local/batches/h2w8/:batchId", readBatch);

async function readBatch(req: Request, res: Response) {
  return loadBatchFile(req);
}

async function loadBatchFile(req: Request) {
  const record = await batchesStore.load(req.params.batchId);
  if (record.tenantId !== req.user.tenantId) {
    return null;
  }
  return sendFile(req.params.batchId);
}
