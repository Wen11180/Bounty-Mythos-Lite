# Mealie recipe API source facts (v3.20.1)

## Endpoint
- GET/PUT/DELETE /recipes/{slug} via RecipeController handlers
- Local modeling route: /local/mealie/api/recipes/{id}

## Read path (get_one)
1. service.get_one(slug) -> group_recipes.get_one (group_id scoped repository)
2. No separate can_view ownership gate beyond group membership / auth middleware
3. Cross-group recipe id/slug fails closed via group-scoped repo

## Update path (_pre_update_check + can_update)
1. get_one loads recipe inside group
2. can_update([slug]) must be true else PermissionDenied
3. can_update allows:
   - recipe.user_id == current user (owner)
   - else if locked -> deny
   - else if owner household != current household AND lock_recipe_edits_from_other_households -> deny
   - else allow collaborative edit
4. lock/unlock settings changes require can_lock_unlock (owner only)

## Delete path (delete_many + can_delete)
1. get_one then can_delete([slugs])
2. admin short-circuit OR count of owned recipes (user_id + group_id) equals request length
3. Fail closed PermissionDenied when not owner

## Security contact
- SECURITY.md: GitHub private vulnerability reporting enabled on mealie-recipes/mealie
