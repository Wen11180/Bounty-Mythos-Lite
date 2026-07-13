import { Router } from "express";

// Educational local snapshot only.
// Pattern: resource export by object id without an ownership guard before the sink.
const router = Router();

router.get("/local/invoices/m8r3/:invoice_id", export_invoice);

async function export_invoice(req: Request, res: Response) {
  // Missing object ownership check before sensitive export.
  return export_file(req.params.invoice_id);
}
