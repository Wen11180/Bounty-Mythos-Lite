import express from "express";

const app = express();

app.patch("/internal/releases/x9g2/:releaseId/approve", approveRelease);

const approveRelease = async (req: Request, res: Response) => {
  return applyRelease(req);
};

const applyRelease = async (req: Request) => {
  const record = await releasesStore.load(req.params.releaseId);
  if (req.user.role !== "reviewer") {
    return null;
  }
  return update(req.params.releaseId);
};
