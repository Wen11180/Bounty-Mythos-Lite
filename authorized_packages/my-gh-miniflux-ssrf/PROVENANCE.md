# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: miniflux/v2.
2. Miniflux publishes SECURITY.md with GitHub private vulnerability reporting and security@miniflux.net.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v2.3.2** source excerpts under _upstream/:
- internal/urllib/url.go (IsNonPublicIP)
- internal/http/client/client.go (BlockPrivateNetworks DialContext)
- internal/reader/fetcher/request_builder.go (ExecuteRequest + private-network dial control)
- internal/validator/feed.go (absolute URL validation)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
No live outbound targets.
