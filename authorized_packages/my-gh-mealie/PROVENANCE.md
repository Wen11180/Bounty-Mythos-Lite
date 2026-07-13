# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: mealie-recipes/mealie.
2. Mealie publishes SECURITY.md with private vulnerability reporting enabled.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream tag **v3.20.1** source excerpts under _upstream/:
- mealie/services/recipe/recipe_service.py (can_update, can_delete, update_one, delete_many)
- mealie/routes/recipe/recipe_crud_routes.py (get_one, update_one, delete_one handlers)
- mealie/routes/recipe/_base.py (group-scoped RecipeService wiring)
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.
