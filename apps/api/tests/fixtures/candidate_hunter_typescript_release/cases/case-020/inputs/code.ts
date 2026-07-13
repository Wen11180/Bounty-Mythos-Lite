import express from "express";

const app = express();

app.get("/internal/catalog/j7q3/:catalogId", readCatalog);

const readCatalog = async (req: Request, res: Response) => {
  const record = await locateCatalog(req.params.catalogId);
  return sendFile(record.path);
};

const locateCatalog = async (catalogId: string) => {
  return catalogStore.load(catalogId, { visibility: "public" });
};
