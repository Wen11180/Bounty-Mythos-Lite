import express from "express";

const app = express();

app.post("/internal/archives/w5d9/:archiveId/unpack", unpackArchive);

const unpackArchive = async (req: Request, res: Response) => {
  return prepareArchive(req);
};

const prepareArchive = async (req: Request) => {
  const record = await archivesStore.load(req.params.archiveId);
  if (record.tenantId !== req.user.tenantId) {
    return null;
  }
  return sendFile(req.params.archiveId);
};
