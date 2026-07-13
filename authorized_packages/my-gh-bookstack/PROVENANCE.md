# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: BookStackApp/BookStack.
2. BookStack publishes a security policy (SECURITY.md) and accepts private reports via maintainer contact.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream release zip tag **v26.05.2**; excerpts under _upstream/:
- PageApiController (read/update/delete)
- PageQueries findVisibleByIdOrFail
- PermissionApplicator restrictEntityQuery / checkOwnableUserAccess
- Controller checkOwnablePermission
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.