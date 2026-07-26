import { Router } from "express";

const router = Router();

router.get("/local/packets/p8x3/:packetId", readPacket);
router.get("/local/packets/p8x3/:packetId/preview", previewPacket);

async function readPacket(req: Request, res: Response) {
  return servePacket(req.params.packetId);
}

async function previewPacket(req: Request, res: Response) {
  return servePacket(req.params.packetId);
}

async function servePacket(packetId: string) {
  return sendFile(packetId);
}
