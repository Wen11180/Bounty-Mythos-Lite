# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: hedgedoc/hedgedoc.
2. HedgeDoc publishes SECURITY.md with private OpenPGP reporting to SISheogorath.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v1.11.0** (package.json version) source excerpts under _upstream/:
- lib/web/note/util.js (findNote + checkViewPermission)
- lib/web/note/controller.js / router.js
- lib/realtime.js (mayEdit permission switch)
- lib/models/note.js (permissionTypes)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.