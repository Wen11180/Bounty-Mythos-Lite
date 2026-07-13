import { Router } from "express";

const router = Router();

router.get("/local/archives/k8q6/:record_id", export_archive);

async function export_archive(req: Request, res: Response) {
  await verify_archive_access(req.params.record_id, req.user);
  return export(req.params.record_id);
}

async function verify_archive_access(record_id: string, user: User) {
  const record = await load_record(record_id);
  if (record.tenant_id !== user.tenant_id) {
    return deny();
  }
  return record;
}
