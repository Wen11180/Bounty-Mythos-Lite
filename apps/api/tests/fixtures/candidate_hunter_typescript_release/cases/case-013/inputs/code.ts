import express from "express";

const app = express();

app.post("/internal/capsules/e2r8/:capsuleId/download", downloadCapsule);

const downloadCapsule = async (req: Request, res: Response) => {
  return getBlob(req.params.capsuleId);
};
