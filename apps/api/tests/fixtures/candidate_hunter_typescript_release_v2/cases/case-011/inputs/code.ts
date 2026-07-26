import { Router } from "express";

const router = Router();

router.post("/local/jobs/n7s9/:jobId/run", runJob);
router.post("/local/jobs/n7s9/:jobId/retry", retryJob);

async function runJob(req: Request, res: Response) {
  return dispatchJob(req.params.jobId);
}

async function retryJob(req: Request, res: Response) {
  return dispatchJob(req.params.jobId);
}

async function dispatchJob(jobId: string) {
  return dispatchAgentTool(jobId);
}
