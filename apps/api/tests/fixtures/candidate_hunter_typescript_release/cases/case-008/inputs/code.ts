import { Router } from "express";

const router = Router();

router.get("/local/snapshots/t3f5/:snapshotId", readSnapshot);

async function readSnapshot(req: Request, res: Response) {
  const record = await findSnapshot(req.params.snapshotId);
  return sendFile(record.path);
}

async function findSnapshot(snapshotId: string) {
  return snapshotsStore.load(snapshotId, { visibility: "public" });
}
