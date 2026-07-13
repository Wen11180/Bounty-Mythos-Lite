import { Router } from "express";

// Local modeling excerpt derived from public knadh/listmonk v6.2.0 sources:
// - internal/core/core.go (makeSearchString / makeSearchQuery)
// - internal/core/campaigns.go (QueryCampaigns -> db.Select with queryStr param)
// - queries/campaigns.sql (query-campaigns: TO_TSQUERY($4) / ILIKE $4 bound param)
// Faithful simplified model of campaign search injection defense:
//   1. User-controlled search string reaches QueryCampaigns
//   2. makeSearchString sanitizes / wraps for tsquery + ILIKE
//   3. SQL template uses bound parameter $4 — not string-concatenated clauses
// Fail closed: deny() when sanitization yields unsafe empty structural input.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type LabUser = {
  id: string;
};

const router = Router();

router.get(
  "/local/listmonk/api/campaigns/search",
  search_local_listmonk_campaigns,
);
router.get(
  "/local/listmonk/api/campaigns/query-preview",
  preview_local_listmonk_campaign_query,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models regexFullTextQuery cleanup used by makeSearchString
function regex_full_text_query(raw: string): string {
  // strip characters that break tsquery structure; keep alnum/space
  return String(raw || "").replace(/[^\w\s-]/g, " ").trim();
}

// models makeSearchString from internal/core/core.go
// prepares a search string for use in both tsquery and ILIKE queries
function makeSearchString(searchStr: string): string {
  if (!searchStr) {
    return "";
  }
  const cleaned = regex_full_text_query(searchStr);
  if (!cleaned) {
    return deny();
  }
  return `%${cleaned}%`;
}

// models makeSearchQuery: sanitize then return bound search param (not SQL text)
function prepare_search_query(searchStr: string) {
  const safe = makeSearchString(searchStr);
  if (safe === undefined || safe === null) {
    return deny();
  }
  return safe;
}

// models c.db.Select / QueryCampaigns with bound $4 parameter
// Sink name is pure injection-family so gap root_cause selects missing_injection_validation
function run_sql(bound_search: string) {
  return { rows: [], bound: bound_search };
}

// models QueryCampaigns search path
async function search_local_listmonk_campaigns(req: Request, res: Response) {
  const raw = String((req as any).query?.q || (req as any).query?.query || "");
  const safe = prepare_search_query(raw);
  return run_sql(safe);
}

// second route for residual: preview still sanitizes before sink
async function preview_local_listmonk_campaign_query(req: Request, res: Response) {
  const raw = String((req as any).body?.query || (req as any).query?.q || "");
  const safe = prepare_search_query(raw);
  return run_sql(safe);
}
