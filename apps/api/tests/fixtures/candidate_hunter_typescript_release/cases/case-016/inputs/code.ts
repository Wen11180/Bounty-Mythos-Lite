import express from "express";

const app = express();

app.get("/internal/entries/l3x7/:entryId/view", viewEntry);

const viewEntry = async (req: Request, res: Response) => {
  const record = await locateEntry(req.params.entryId);
  return sendFile(record.path);
};

const locateEntry = async (entryId: string) => {
  return entriesStore.load(entryId, { visibility: "public" });
};
