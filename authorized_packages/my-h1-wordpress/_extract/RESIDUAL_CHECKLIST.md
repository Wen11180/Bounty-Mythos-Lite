# Residual version-diff checklist (WordPress Core)

Use only on a local WordPress Core source tree authorized for SOURCE_CODE research.
No wordpress.com and no other people's sites.

Companion: `docs/hunter-ab-residual-runbook.md` section 4
Facts: `SOURCE_FACTS.md`

## Version pin

- Core version / commit: **7.1-alpha-62695** (WordPress/WordPress master `wp-includes/version.php`, fetched 2026-07-12)
- Date checked: 2026-07-12
- Tree source: public GitHub raw `WordPress/WordPress` REST endpoint files under `_upstream/`

## Control matrix

| ID | Control point | Status | Notes |
| --- | --- | --- | --- |
| WP-1 | get_post invalid id handling | **present** | `(int)$id <= 0` / empty post / wrong post_type -> `rest_post_invalid_id` 404 |
| WP-2 | get_item_permissions_check / check_read_permission | **present** | get_post then `check_read_permission`; edit context needs update permission |
| WP-3 | update_item_permissions_check / edit_post | **present** | `check_update_permission` -> `current_user_can('edit_post', post.ID)` |
| WP-4 | delete_item_permissions_check / delete_post | **present** | `check_delete_permission` -> `current_user_can('delete_post', post.ID)` |
| WP-5 | author change elevated capability | **present** | author change requires `edit_others_posts` |
| WP-6 | publish vs draft/private boundary | **present** | read allows publish/public status or `read_post` capability; inherit recurses parent |

## Residual hypotheses (if any)

1. None for Core REST posts controller control points above on 7.1-alpha-62695.
2. Plugin overrides / custom post type controllers remain out of this Core excerpt (separate research decision).

## Scope notes

- Core only unless you explicitly expand scope.
- Plugin-only paths are a separate decision.
- Not wordpress.com production.

## Safety

- [x] local-only materials (public Core sources staged locally)
- [x] no real user private data
- [x] no destructive tests
- [x] report submission blocked

## Result

- [x] controls still hold (zero residual)
- [ ] residual hypothesis written for human review