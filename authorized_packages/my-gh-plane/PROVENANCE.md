# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: makeplane/plane.
2. Plane publishes SECURITY.md with private security@plane.so reporting.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v1.3.1** (package.json on preview tree) source excerpts under _upstream/:
- apps/api/plane/app/permissions/base.py (allow_permission + ROLE enum)
- apps/api/plane/app/views/issue/base.py (retrieve/partial_update/destroy)
- apps/api/plane/app/views/base.py
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.