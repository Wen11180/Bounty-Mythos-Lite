import express from "express";

const app = express();

app.post("/internal/workflows/u4n8/:workflowId/execute", executeWorkflow);

const executeWorkflow = async (req: Request, res: Response) => {
  return executeAgentTool(req.params.workflowId);
};
