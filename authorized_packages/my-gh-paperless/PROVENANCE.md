# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: paperless-ngx/paperless-ngx.
2. paperless-ngx publishes SECURITY.md with private GitHub Security Advisory reporting.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream tag **v2.9.0** source excerpts under _upstream/:
- src/documents/permissions.py (PaperlessObjectPermissions, has_perms_owner_aware)
- src/documents/views.py (DocumentViewSet)
- src/documents/filters.py (ObjectOwnedOrGrantedPermissionsFilter)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
