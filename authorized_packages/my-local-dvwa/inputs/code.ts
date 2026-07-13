import { Router } from "express";

// Local modeling excerpt derived from researcher-owned DVWA container sources
// (mythos-dvwa / vulnerables/web-dvwa). Intentionally vulnerable teaching app.
// Models low-level object-id export without ownership gate (id lookup class).
// Used only for authorized local static review. Not a public production target.
// Not a bounty submission package.

type UserRecord = {
  id: string;
  owner_id: string;
  display_name: string;
};

const router = Router();

router.get("/local/dvwa/users/:user_id/export", export_local_dvwa_user);

function find_user(user_id: string): UserRecord | null {
  if (!user_id) {
    return null;
  }
  return {
    id: user_id,
    owner_id: "owner-lab-1",
    display_name: "lab-user",
  };
}

// models DVWA low-level user_id access without ownership boundary
async function export_local_dvwa_user(req: Request, res: Response) {
  const record = find_user(req.params.user_id);
  return export_file(record.id);
}