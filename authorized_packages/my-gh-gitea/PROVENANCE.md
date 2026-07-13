# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: go-gitea/gitea.
2. Gitea publishes SECURITY.md and accepts private reports at security@gitea.io.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream excerpts under `_upstream/`:
- issue GetIssue handler excerpt
- permission middleware / CanRead helpers
- SECURITY.md (contact policy; PGP block omitted)

## What enters the hunter
Only `inputs/*` and `package.json`.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
