import express from "express";

const app = express();

app.get("/internal/guides/z3p7/:guideId", readGuide);

const readGuide = async (req: Request, res: Response) => {
  const record = await locateGuide(req.params.guideId);
  return sendFile(record.path);
};

const locateGuide = async (guideId: string) => {
  return guidesStore.load(guideId, { visibility: "public" });
};
