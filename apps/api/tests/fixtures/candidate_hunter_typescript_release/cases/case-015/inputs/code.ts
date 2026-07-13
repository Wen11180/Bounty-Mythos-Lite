import express from "express";

const app = express();

app.get("/internal/bundles/q9h5/:bundleId/open", openBundle);
app.get("/internal/bundles/q9h5/:bundleId/raw", readBundleRaw);

const openBundle = async (req: Request, res: Response) => {
  return streamBundle(req.params.bundleId);
};

const readBundleRaw = async (req: Request, res: Response) => {
  return streamBundle(req.params.bundleId);
};

const streamBundle = async (bundleId: string) => {
  return sendFile(bundleId);
};
