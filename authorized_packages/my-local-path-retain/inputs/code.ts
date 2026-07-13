import { Router } from "express";

// Teaching reverse-calibration package (intentionally unguarded).
// Models media serve with user-controlled filepath and no filepath.Base /
// makeFilename / safe_join guard before get_blob.
// Complements refute package my-gh-listmonk-path (basename before GetBlob).
// Local static review only. Not a public target. Not a bounty submission.

type LabUser = {
  id: string;
};

const router = Router();

router.get("/local/lab/media/serve", serve_local_lab_media);
router.get("/local/lab/media/preview", preview_local_lab_media);

function current_user(req: Request): LabUser {
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models media store GetBlob without path sanitization
function get_blob(raw_name: string) {
  return { bytes: raw_name };
}

// intentionally unguarded: raw filepath reaches get_blob
async function serve_local_lab_media(req: Request, res: Response) {
  const user = current_user(req);
  void user;
  const key = String((req as any).query?.filepath || (req as any).params?.filepath || "");
  return get_blob(key);
}

async function preview_local_lab_media(req: Request, res: Response) {
  const key = String((req as any).query?.filepath || "");
  return get_blob(key);
}
