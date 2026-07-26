import { Router } from "express";

const router = Router();

router.get("/local/cards/r5n7/:cardId", readCard);

async function readCard(req: Request, res: Response) {
  const record = await findCard(req.params.cardId);
  return sendFile(record.path);
}

async function findCard(cardId: string) {
  return cardsStore.load(cardId, { visibility: "public" });
}
