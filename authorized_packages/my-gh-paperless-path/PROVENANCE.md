# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: paperless-ngx/paperless-ngx.
2. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
3. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v2.9.0** source excerpts under _upstream/:
- src/documents/file_handling.py (pathvalidate.sanitize_filename in generate_filename)
- src/documents/models.py (source_path / get_public_filename excerpt)
- src/documents/consumer.py (generate_unique_filename write path excerpt)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
No live host path pivots.
No raw http:// or https:// URL literals in inputs (fixture sanitizer).
