import { Router } from "express";

const router = Router();

router.get("/local/ledgers/k4v9/:ledgerId/file", fetchLedger);

async function fetchLedger(req: Request, res: Response) {
  return resolveLedger(req);
}

async function resolveLedger(req: Request) {
  const record = await ledgersStore.load(req.params.ledgerId);
  if (record.ownerId !== req.user.id) {
    return null;
  }
  return sendFile(req.params.ledgerId);
}
