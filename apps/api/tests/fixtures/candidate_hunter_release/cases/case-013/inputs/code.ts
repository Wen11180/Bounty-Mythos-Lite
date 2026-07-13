import { Router } from "express";

const router = Router();

router.get("/local/transfers/p4x8/:record_id", transfer_funds);

async function transfer_funds(req: Request, res: Response) {
  return transfer(req.params.record_id);
}