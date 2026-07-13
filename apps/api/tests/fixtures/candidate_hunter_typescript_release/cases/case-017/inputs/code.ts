import express from "express";

const app = express();

app.post("/internal/exports/f8m1/:exportId/download", downloadExport);

const downloadExport = async (req: Request, res: Response) => {
  return sendFile(req.params.exportId);
};
