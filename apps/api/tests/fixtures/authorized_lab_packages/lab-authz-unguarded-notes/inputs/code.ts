import { Router } from "express";

const router = Router();

router.get("/local/notes/k2p1/:note_id", read_note);

async function read_note(req: Request, res: Response) {
  return send_file(req.params.note_id);
}
