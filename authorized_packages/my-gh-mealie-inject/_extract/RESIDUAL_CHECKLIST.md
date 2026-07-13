# Residual checklist ? my-gh-mealie-inject (optional)

Static package trial expected **refute** (SearchFilter + QueryFilterBuilder binds present before run_sql).

| ID | Question | Static status |
| --- | --- | --- |
| ME-INJ-R1 | SearchFilter normalizes/tokenizes before filter_query_by_search? | **held** (query_search.py) |
| ME-INJ-R2 | Search reaches ORM as bound values (not string-concat SQL)? | **held** (add_search_to_query / schema.filter_search_query) |
| ME-INJ-R3 | QueryFilterBuilder validates attribute types before sa bind? | **held** (builder.py validate) |
| ME-INJ-R4 | Empty search short-circuits or yields no-op filter? | **held** (empty tokens / model deny) |
| ME-INJ-R5 | Order_by restricted / separate from free-text search residual? | **held_documented** (add_order_by_to_query path) |
| ME-INJ-R6 | Any raw string-concat SQL for user search residual? | **held_documented** (parameterized ORM path) |

Live residual: researcher-owned loopback only; no destructive SQL.
