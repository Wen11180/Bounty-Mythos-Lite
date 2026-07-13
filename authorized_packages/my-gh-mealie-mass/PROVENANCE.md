# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: mealie-recipes/mealie.
2. Mealie publishes SECURITY.md with private vulnerability reporting.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v3.20.1** source excerpts under _upstream/:
- mealie/routes/users/crud.py
- mealie/routes/users/_helpers.py
- mealie/schema/user/user.py (or excerpt)

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
No live privilege-escalation against third parties.