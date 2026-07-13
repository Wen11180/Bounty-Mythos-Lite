import { Router } from "express";

const router = Router();

router.get("/local/folios/a7m2/:folioId", readFolio);

async function readFolio(req: Request, res: Response) {
  return sendFile(req.params.folioId);
}
