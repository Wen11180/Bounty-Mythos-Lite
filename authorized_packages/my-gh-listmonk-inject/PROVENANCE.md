# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: knadh/listmonk.
2. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
3. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v6.2.0** source excerpts under _upstream/:
- internal/core/core.go (makeSearchString / makeSearchQuery)
- internal/core/campaigns.go (QueryCampaigns)
- queries/campaigns.sql (query-campaigns bound $4)

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
No live destructive SQL.
