# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: knadh/listmonk.
2. listmonk publishes SECURITY.md and security-report guidance.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream release zip tag **v6.2.0**; excerpts under _upstream/:
- cmd/campaigns.go (GetCampaign, checkCampaignPerm)
- internal/core/campaigns.go (CampaignHasLists)
- internal/auth models/auth helpers
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.