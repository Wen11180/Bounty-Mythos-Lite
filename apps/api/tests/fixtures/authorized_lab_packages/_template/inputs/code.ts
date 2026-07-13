import { Router } from "express";

const router = Router();

// Replace with authorized local TypeScript you may analyze.
// Sensitive sinks the mapper knows: send_file, export_file, transfer, update, delete, ...
router.get("/local/REPLACE/:id", replace_handler);

async function replace_handler(req: Request, res: Response) {
  return send_file(req.params.id);
}
