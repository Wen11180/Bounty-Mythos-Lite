# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: laurent22/joplin.
2. Joplin publishes SECURITY.md with private vulnerability reporting.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v3.7.1** (@joplin/server package.json) source excerpts under _upstream/:
- packages/server/src/models/ItemModel.ts
- packages/server/src/models/ShareModel.ts
- packages/server/src/routes/api/items.ts
- packages/server/src/routes/api/shares.ts
- packages/server/src/models/BaseModel.ts
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.