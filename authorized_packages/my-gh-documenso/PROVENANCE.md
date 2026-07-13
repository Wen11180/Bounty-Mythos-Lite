# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: documenso/documenso.
2. Documenso publishes SECURITY.md with private GitHub advisory / security@documenso.com reporting.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream tag **v2.14.0** source excerpts under _upstream/:
- packages/lib/server-only/envelope/get-envelope-by-id.ts (getEnvelopeWhereInput)
- packages/lib/server-only/document/delete-document.ts (hasDeleteAccess)
- packages/trpc/server/document-router get/update/delete
- packages/lib/constants/teams.ts TEAM_DOCUMENT_VISIBILITY_MAP
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.