import { Router } from "express";

const router = Router();

router.get("/local/transfers/c6w5/:record_id", transfer_funds);
router.get("/local/transfers/c6w5/:record_id/summary", transfer_funds_summary);

async function transfer_funds(req: Request, res: Response) {
  return load_transfer(req.params.record_id);
}

async function transfer_funds_summary(req: Request, res: Response) {
  return load_transfer(req.params.record_id);
}

async function load_transfer(record_id: string) {
  return transfer(record_id);
}