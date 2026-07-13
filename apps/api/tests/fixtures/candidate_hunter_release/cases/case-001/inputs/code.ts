import { Router } from "express";

const router = Router();

router.get("/local/records/q7m4/:record_id", read_record);

async function read_record(req: Request, res: Response) {
  return send_file(req.params.record_id);
}