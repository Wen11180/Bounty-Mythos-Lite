import { Router } from "express";

// Teaching reverse-calibration package (intentionally unguarded).
// Models campaign search with user-controlled query string and no
// makeSearchString / parameterize / bind_query guard before run_sql.
// Complements refute package my-gh-listmonk-inject (makeSearchString + bound $4).
// Local static review only. Not a public target. Not a bounty submission.

type LabUser = {
  id: string;
};

const router = Router();

router.get("/local/lab/campaigns/search", search_local_lab_campaigns);
router.get("/local/lab/campaigns/query-preview", preview_local_lab_campaign_query);

function current_user(req: Request): LabUser {
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models c.db.Select / execute without sanitization
function run_sql(raw_search: string) {
  return { rows: [], query: raw_search };
}

// intentionally unguarded: raw q reaches run_sql
async function search_local_lab_campaigns(req: Request, res: Response) {
  const user = current_user(req);
  void user;
  const raw = String((req as any).query?.q || (req as any).query?.query || "");
  return run_sql(raw);
}

async function preview_local_lab_campaign_query(req: Request, res: Response) {
  const raw = String((req as any).body?.query || (req as any).query?.q || "");
  return run_sql(raw);
}
