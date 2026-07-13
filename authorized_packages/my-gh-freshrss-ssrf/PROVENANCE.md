# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: FreshRSS/FreshRSS.
2. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
3. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **1.29.1** source excerpts under _upstream/:
- lib/Minz/Request.php (serverIsPublic)
- app/Utils/httpUtil.php (checkUrl / httpGet)
- app/Models/Feed.php (feed URL load path)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
No live URL scheme literals in inputs (http/https split-concat in code model).
No real outbound SSRF pivots.
