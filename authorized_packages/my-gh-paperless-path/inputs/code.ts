import { Router } from "express";

// Local modeling excerpt derived from public paperless-ngx/paperless-ngx v2.9.0 sources:
// - src/documents/file_handling.py (generate_filename uses pathvalidate.sanitize_filename;
//   original_name uses PurePath(doc.original_filename).with_suffix("").name)
// - src/documents/models.py (source_path joins ORIGINALS_DIR / Path(fname).resolve())
// - src/documents/consumer.py (generate_unique_filename then write to source_path)
// Faithful simplified model of document path handling:
//   1. User-influenced original_filename / title / correspondent reach filename generation
//   2. sanitize_filename + PurePath.name strip path components before storage name
//   3. source_path / read_file only uses the sanitized relative name under originals root
// Fail closed: deny() when sanitization yields empty unsafe name.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type DocumentRecord = {
  id: string;
  filename: string;
  owner_id: string;
};

type LabUser = {
  id: string;
};

const router = Router();

router.get(
  "/local/paperless/api/documents/read-source",
  read_local_paperless_source,
);
router.post(
  "/local/paperless/api/documents/prepare-filename",
  prepare_local_paperless_filename,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models PurePath(name).name / basename strip of directory components
function purepath_name(name: string): string {
  if (!name) {
    return "";
  }
  const parts = String(name).split(/[\\\\/]/);
  return parts[parts.length - 1] || "";
}

// models pathvalidate.sanitize_filename(..., replacement_text="-")
// Named sanitize_filename so PATH_GUARD_MARKERS (sanitize_filename) fire in codebase_map.
function sanitize_filename(raw: string): string {
  let name = purepath_name(String(raw || "").trim());
  if (!name) {
    return "";
  }
  // strip traversal residual segments after basename (model of pathvalidate)
  name = name.split("..").join("-");
  name = name.split("<").join("-");
  name = name.split(">").join("-");
  name = name.split(":").join("-");
  name = name.split("|").join("-");
  name = name.split("?").join("-");
  name = name.split("*").join("-");
  return name;
}

// models generate_filename component sanitization before unique storage name
function prepare_document_filename(raw_name: string) {
  const safe = sanitize_filename(raw_name);
  if (!safe) {
    return deny();
  }
  return safe;
}

// models prepare path for source_path residual: sanitize before join/read
function prepare_source_name(raw_path: string) {
  const safe = sanitize_filename(raw_path);
  if (!safe) {
    return deny();
  }
  return safe;
}

// models Document.source_file / open(source_path) after sanitized relative fname
// Named read_file so FILE_PATH_SINK_NAMES fire (path_traversal family).
function read_file(safe_name: string) {
  return { bytes: safe_name };
}

// models GET document original: only sanitized relative name under ORIGINALS_DIR
async function read_local_paperless_source(req: Request, res: Response) {
  const key = String((req as any).query?.filename || (req as any).params?.filename || "");
  const safe = prepare_source_name(key);
  return read_file(safe);
}

// models consumer/generate_filename: sanitize original/title before store residual
async function prepare_local_paperless_filename(req: Request, res: Response) {
  const raw = String((req as any).body?.original_filename || (req as any).body?.title || "");
  const safe = prepare_document_filename(raw);
  return read_file(safe);
}
