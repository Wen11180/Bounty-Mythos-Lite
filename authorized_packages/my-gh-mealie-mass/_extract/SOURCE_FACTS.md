# Source facts — my-gh-mealie-mass

- Upstream: mealie-recipes/mealie **v3.20.1**
- Route: PUT /users/{item_id} (`UserController.update_user`) with `UserBase` body
- Sink: `repos.users.update(item_id, new_data.model_dump())` (modeled `update_user`)
- Primary control: `assert_user_change_allowed` before update
- permission_attrs: admin, can_invite, can_manage, can_manage_household, can_organize
- Non-admin: self-only; cannot change privilege attrs / group / household
- Admin via this route: self-only; cannot change own permission_attrs (Admin API for others)
- Package models guard-before-update for expected **refute**