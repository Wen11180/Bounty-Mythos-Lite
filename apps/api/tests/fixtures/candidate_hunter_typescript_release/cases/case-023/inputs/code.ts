import express from "express";

const app = express();

app.post("/internal/tasks/c6t5/:taskId/execute", executeTask);
app.post("/internal/tasks/c6t5/:taskId/replay", replayTask);

const executeTask = async (req: Request, res: Response) => {
  return launchTask(req.params.taskId);
};

const replayTask = async (req: Request, res: Response) => {
  return launchTask(req.params.taskId);
};

const launchTask = async (taskId: string) => {
  return executeAgentTool(taskId);
};
