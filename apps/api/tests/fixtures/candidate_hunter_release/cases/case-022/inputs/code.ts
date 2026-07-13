import { Router } from "express";

const router = Router();

router.get("/local/tools/e9c3/:record_id", run_tool);

async function run_tool(req: Request, res: Response) {
  await verify_tool_access(req.params.record_id, req.user);
  return execute_agent_tool(req.params.record_id);
}

async function verify_tool_access(record_id: string, user: User) {
  const record = await load_record(record_id);
  if (record.tenant_id !== user.tenant_id) {
    return deny();
  }
  return record;
}
