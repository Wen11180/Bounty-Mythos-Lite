# Source facts — my-gh-listmonk-inject

- Upstream: knadh/listmonk **v6.2.0**
- Path: QueryCampaigns(searchStr, ...) in internal/core/campaigns.go
- Sanitizer: makeSearchString / makeSearchQuery in internal/core/core.go
- SQL: queries/campaigns.sql `query-campaigns` uses bound `$4` for TO_TSQUERY / ILIKE
- Sink modeled: run_sql (db.Select)
- Control modeled: makeSearchString before sink
- Package models sanitize-before-query for expected **refute**
