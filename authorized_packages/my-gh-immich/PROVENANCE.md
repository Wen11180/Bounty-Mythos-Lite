# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: immich-app/immich.
2. Immich publishes SECURITY.md with private security@immich.app reporting.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream tag **v2.7.5** source excerpts under _upstream/:
- server/src/utils/access.ts (requireAccess / checkAccess AssetRead|Update|Delete)
- server/src/repositories/access.repository.ts (AssetAccess.checkOwnerAccess / album / partner)
- server/src/services/asset.service.ts (get / update / deleteAll)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
