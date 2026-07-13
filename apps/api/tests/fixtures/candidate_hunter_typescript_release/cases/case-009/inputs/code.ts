import { Router } from "express";

const router = Router();

router.delete("/local/consoles/d8j4/:consoleId", removeConsole);

async function removeConsole(req: Request, res: Response) {
  return deleteFile(req.params.consoleId);
}
