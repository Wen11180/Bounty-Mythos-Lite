import { Router } from "express";

const router = Router();

router.get("/local/tools/a6p2/:record_id", run_tool);

async function run_tool(req: Request, res: Response) {
  const record = await load_public_tool_job(req.params.record_id);
  return execute_agent_tool(record.path);
}

async function load_public_tool_job(record_id: string) {
  return record_store.get(record_id, { visibility: "public" });
}