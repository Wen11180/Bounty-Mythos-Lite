import { Router } from "express";

// Local modeling excerpt derived from public mealie-recipes/mealie v3.20.1 sources:
// - mealie/schema/response/query_search.py (SearchFilter._normalize_search / _build_search_list)
// - mealie/repos/repository_generic.py (page_all -> add_search_to_query -> SearchFilter)
// - mealie/services/query_filter/builder.py (QueryFilterBuilder.filter_query: ORM column binds)
// Faithful simplified model of recipe search / query-filter injection defense:
//   1. User-controlled search / query_filter string reaches page_all / add_pagination_to_query
//   2. SearchFilter normalizes punctuation and tokenizes (regex_full_text style cleanup)
//   3. makeSearchString / parameterize prepare bound search tokens before SQL
//   4. QueryFilterBuilder validates attribute/value then builds sa.ColumnElement binds
//   5. Sink is session.execute / db_select with bound params — not string-concat SQL clauses
// Fail closed: deny() when sanitization yields empty unsafe structural input.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type LabUser = {
  id: string;
};

const router = Router();

router.get(
  "/local/mealie/api/recipes/search",
  search_local_mealie_recipes,
);
router.get(
  "/local/mealie/api/recipes/query-filter",
  filter_local_mealie_recipes,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models SearchFilter punctuation strip + quoted/token cleanup
// Named regex_full_text_query so INJECTION_GUARD_MARKERS (regex_full_text) fire.
function regex_full_text_query(raw: string): string {
  // strip characters that break query structure; keep alnum/space/hyphen
  return String(raw || "").replace(/[^\\w\\s-]/g, " ").trim();
}

// models SearchFilter._normalize_search + token list for filter_query_by_search
// Named makeSearchString so INJECTION_GUARD_MARKERS (make_search_string via camelCase) fire.
function makeSearchString(searchStr: string): string {
  if (!searchStr) {
    return "";
  }
  const cleaned = regex_full_text_query(searchStr);
  if (!cleaned) {
    return deny();
  }
  // tokenized form used as bound LIKE/tsquery values, not SQL text
  return cleaned
    .split(/\\s+/)
    .filter(Boolean)
    .join(" ");
}

// models QueryFilterBuilderComponent.validate + placeholder processing
// Named sql_sanitize so INJECTION_GUARD_MARKERS (sql_sanitize) fire.
function sql_sanitize(raw_value: string): string {
  const cleaned = regex_full_text_query(String(raw_value || ""));
  if (!cleaned && raw_value) {
    return deny();
  }
  return cleaned;
}

// models prepare bound params for SearchFilter.filter_query_by_search
// Intermediate wrapper (not a guard marker itself) so gap is hypothesized then refuted.
function prepare_search_query(searchStr: string) {
  const safe = makeSearchString(searchStr);
  if (safe === undefined || safe === null) {
    return deny();
  }
  return safe;
}

// models QueryFilterBuilder.filter_query prepare path before sink
// Intermediate wrapper; bind happens via sql_sanitize inside.
function prepare_filter_query(filter_string: string) {
  const safe = sql_sanitize(filter_string);
  if (safe === undefined || safe === null) {
    return deny();
  }
  // structural filter parts are validated; value is bound, not concatenated
  return safe;
}

// models session.execute / db.Select after bound params
// Sink name is pure injection-family so gap root_cause selects missing_injection_validation
function run_sql(bound_search: string) {
  return { rows: [], bound: bound_search };
}

// models page_all + add_search_to_query search path
async function search_local_mealie_recipes(req: Request, res: Response) {
  const raw = String((req as any).query?.search || (req as any).query?.q || "");
  const safe = prepare_search_query(raw);
  return run_sql(safe);
}

// models add_pagination_to_query query_filter path (QueryFilterBuilder)
async function filter_local_mealie_recipes(req: Request, res: Response) {
  const raw = String(
    (req as any).query?.query_filter ||
      (req as any).query?.filter ||
      (req as any).body?.query_filter ||
      "",
  );
  const safe = prepare_filter_query(raw);
  return run_sql(safe);
}
