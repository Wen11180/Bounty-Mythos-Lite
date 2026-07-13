# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: makeplane/plane.
2. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
3. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v1.3.1** source excerpts under _upstream/:
- apps/api/plane/app/serializers/user.py (UserSerializer read_only privilege fields)
- apps/api/plane/app/views/user/base.py (UserEndpoint.partial_update)
- apps/api/plane/db/models/user.py
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
