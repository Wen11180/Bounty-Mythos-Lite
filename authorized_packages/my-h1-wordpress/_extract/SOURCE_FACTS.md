# Extracted facts from public WordPress Core REST sources

Fetched for local authorized research under HackerOne wordpress Core SOURCE_CODE scope class.
Upstream files stored under _upstream/ (not loaded by Mythos package inputs).

## Version pin (residual 2026-07-12)

- `$wp_version = '7.1-alpha-62695'` from public `wp-includes/version.php`
- Residual matrix: WP-1..WP-6 **present**; zero residual hypotheses
- Report: `docs/hunter-ab-wordpress-local-residual.md`

## class-wp-rest-posts-controller.php

- get_post(id): invalid id returns WP_Error rest_post_invalid_id (404)
- get_item_permissions_check:
  - loads post via get_post
  - edit context requires check_update_permission
  - password query param hash comparison when present
  - returns check_read_permission(post)
- update_item_permissions_check:
  - get_post
  - check_update_permission required
  - author change requires edit_others_posts
- delete_item_permissions_check / delete_item: get_post then check_delete_permission
- check_read_permission:
  - allow if post status publish/public or current_user_can('read_post', post.ID)
  - inherit status may recurse to parent
- check_update_permission: current_user_can('edit_post', post.ID)
- check_delete_permission: current_user_can('delete_post', post.ID)

## Research implications for local Core review

1. Core REST post object operations are not unguarded id-to-sink paths in public source.
2. Capability checks are object-level (read_post / edit_post / delete_post), not bare id presence.
3. Mythos candidates from a faithful model should often REFUTE naive missing-ownership claims.
4. Residual research value is version drift, plugin overrides, or alternate controllers outside this Core excerpt.