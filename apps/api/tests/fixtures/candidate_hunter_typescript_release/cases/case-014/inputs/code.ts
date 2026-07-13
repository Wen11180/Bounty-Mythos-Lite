import express from "express";

const app = express();

app.post("/internal/artifacts/y6b3/:artifactId/render", renderArtifact);

const renderArtifact = async (req: Request, res: Response) => {
  return prepareArtifact(req);
};

const prepareArtifact = async (req: Request) => {
  const record = await artifactsStore.load(req.params.artifactId);
  if (record.ownerId !== req.user.id) {
    return null;
  }
  return sendFile(req.params.artifactId);
};
