import { Router } from "express";

const router = Router();

router.get("/local/notices/v4k6/:noticeId", readNotice);

async function readNotice(req: Request, res: Response) {
  const record = await locateNotice(req.params.noticeId);
  return sendFile(record.path);
}

async function locateNotice(noticeId: string) {
  return noticesStore.load(noticeId, { visibility: "public" });
}
