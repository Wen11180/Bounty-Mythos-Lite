import { Router } from "express";

// Local modeling excerpt derived from public knadh/listmonk v6.2.0 sources:
// - internal/media/providers/filesystem/filesystem.go (GetBlob uses filepath.Base)
// - cmd/media.go (ServeS3Media takes filepath param then GetBlob)
// - cmd/utils.go (makeFilename -> filepath.Base for uploads)
// Faithful simplified model of media path handling:
//   1. User-controlled filepath / filename reaches media store
//   2. Before filesystem join/read, basename strips directory components
//   3. Upload path also sanitizes via makeFilename
// Fail closed: deny() when sanitization yields empty unsafe name.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type MediaRecord = {
  id: string;
  filename: string;
  owner_id: string;
};

type LabUser = {
  id: string;
};

const router = Router();

router.get(
  "/local/listmonk/api/media/serve",
  serve_local_listmonk_media,
);
router.post(
  "/local/listmonk/api/media/upload-name",
  prepare_local_listmonk_upload_name,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models filepath.Base(url) from filesystem.GetBlob
function filepath_base(name: string): string {
  if (!name) {
    return "";
  }
  // strip directory components (basename semantics)
  const parts = String(name).split(/[\\/]/);
  return parts[parts.length - 1] || "";
}

// models makeFilename from cmd/utils.go (spaces -> dash, then Base)
function makeFilename(fName: string): string {
  let name = String(fName || "").trim();
  if (!name) {
    return deny();
  }
  name = name.replace(/[\s]+/g, "-");
  return filepath_base(name);
}

// models prepare path: path sanitization before filesystem read
function prepare_media_path(raw_path: string) {
  const safe = filepath_base(raw_path);
  if (!safe) {
    return deny();
  }
  return safe;
}

// models upload name prepare: makeFilename before store put / read residual
function prepare_upload_name(raw_name: string) {
  const safe = makeFilename(raw_name);
  if (!safe) {
    return deny();
  }
  return safe;
}

// models media store GetBlob after Base
function get_blob(safe_name: string) {
  return { bytes: safe_name };
}

// models ServeS3Media: key := c.Param("filepath"); a.media.GetBlob(key)
// FS provider applies filepath.Base inside GetBlob before join/read.
async function serve_local_listmonk_media(req: Request, res: Response) {
  const key = String((req as any).query?.filepath || (req as any).params?.filepath || "");
  const safe = prepare_media_path(key);
  return get_blob(safe);
}

// models UploadMedia filename sanitization before store; residual sink is get_blob of name
async function prepare_local_listmonk_upload_name(req: Request, res: Response) {
  const raw = String((req as any).body?.filename || "");
  const safe = prepare_upload_name(raw);
  return get_blob(safe);
}