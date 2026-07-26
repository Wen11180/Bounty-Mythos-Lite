import { Router } from "express";

const router = Router();

router.get("/local/invoices/b9q4/:invoiceId/export", exportInvoice);

async function exportInvoice(req: Request, res: Response) {
  return sendFile(req.params.invoiceId);
}
