import { Router } from "express";

const router = Router();

router.get("/local/reports/m6z1/:reportId", readReport);
router.get("/local/reports/m6z1/:reportId/archive", archiveReport);

async function readReport(req: Request, res: Response) {
  return deliverReport(req.params.reportId);
}

async function archiveReport(req: Request, res: Response) {
  return deliverReport(req.params.reportId);
}

async function deliverReport(reportId: string) {
  return sendFile(reportId);
}
