# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: immich-app/immich.
2. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
3. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v2.7.5** source excerpts under _upstream/:
- server/src/dtos/user.dto.ts (UserUpdateMeDto vs UserAdmin*Dto)
- server/src/services/user.service.ts (updateMe field pick)
- server/src/controllers/user.controller.ts (updateMyUser)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
No raw http:// or https:// URL literals in inputs (fixture sanitizer).
