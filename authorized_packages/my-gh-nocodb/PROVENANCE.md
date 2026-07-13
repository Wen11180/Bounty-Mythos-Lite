# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: nocodb/nocodb.
2. NocoDB publishes SECURITY.md with private security@nocodb.com reporting.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream tag **v2026.06.1** source excerpts under _upstream/:
- packages/nocodb/src/controllers/data-table.controller.ts (@Acl dataList/dataUpdate/dataDelete)
- packages/nocodb/src/utils/acl.ts (rolePermissions ProjectRoles VIEWER/EDITOR)
- packages/nocodb/src/middlewares/extract-ids/extract-ids.middleware.ts (canActivate ACL)
- packages/nocodb/src/guards/global/global.guard.ts (GlobalGuard)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.