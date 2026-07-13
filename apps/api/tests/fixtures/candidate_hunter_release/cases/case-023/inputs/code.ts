import { Router } from "express";

const router = Router();

router.get("/local/tools/u1h5/:record_id", run_tool);
router.get("/local/tools/u1h5/:record_id/summary", run_tool_summary);

async function run_tool(req: Request, res: Response) {
  return load_tool_job(req.params.record_id);
}

async function run_tool_summary(req: Request, res: Response) {
  return load_tool_job(req.params.record_id);
}

async function load_tool_job(record_id: string) {
  return execute_agent_tool(record_id);
}