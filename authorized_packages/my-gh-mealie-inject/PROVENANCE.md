# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: mealie-recipes/mealie.
2. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
3. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v3.20.1** source excerpts under _upstream/:
- mealie/schema/response/query_search.py (SearchFilter)
- mealie/repos/repository_generic.py (page_all / add_search_to_query)
- mealie/services/query_filter/builder.py (QueryFilterBuilder)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
No live destructive SQL.
