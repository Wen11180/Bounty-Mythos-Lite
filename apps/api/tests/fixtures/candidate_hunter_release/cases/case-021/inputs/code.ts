import { Router } from "express";

const router = Router();

router.get("/local/tools/s4j8/:record_id", run_tool);

async function run_tool(req: Request, res: Response) {
  return execute_agent_tool(req.params.record_id);
}