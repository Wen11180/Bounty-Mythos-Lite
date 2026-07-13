# A+B Local Residual — WordPress Core REST

Date: 2026-07-12
Package: `authorized_packages/my-h1-wordpress`
Method: read-only public Core source fetch + static control-point scan.
No wordpress.com, no third-party sites, no live exploit payloads.

## Version pin

| Field | Value |
| --- | --- |
| Core | **7.1-alpha-62695** |
| Files | `class-wp-rest-posts-controller.php` (+ attachments/users controllers refreshed) |
| Source | `WordPress/WordPress` public GitHub raw |
| SHA256 posts controller | matches package `_upstream` after refresh (identical to previous staged copy this day) |

## Control matrix

| ID | Expected | Observed on 7.1-alpha-62695 | Residual? |
| --- | --- | --- | --- |
| WP-1 | invalid id -> error | present (`rest_post_invalid_id`) | no |
| WP-2 | get item -> check_read_permission | present | no |
| WP-3 | update -> check_update_permission / edit_post | present | no |
| WP-4 | delete -> check_delete_permission / delete_post | present | no |
| WP-5 | author change elevated cap | present (`edit_others_posts`) | no |
| WP-6 | publish/public vs capability read | present | no |

## Product read

- Unblocks prior **WordPress local residual: Blocked** scoreboard row.
- Aligns with package trial **4/0 all refuted** (faithful guarded model).
- Zero residual bounty hypotheses on this Core REST posts surface.

## Not claimed

- Not a confirmed vulnerability
- Not wordpress.com
- Not automatic submission
- Plugin ecosystem not covered