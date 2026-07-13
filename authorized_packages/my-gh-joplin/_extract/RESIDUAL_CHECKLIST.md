# Residual checklist — my-gh-joplin (optional)

Static package trial expected **refute** (guards present).

| ID | Question | Static status |
| --- | --- | --- |
| JP-R1 | item load scoped by user_items.user_id? | **held** (group_id_filter) |
| JP-R2 | owner_id short-circuit holds? | **held** (owner_id_filter) |
| JP-R3 | shared delete requires share owner or accepted participant? | **held** (modeled) |
| JP-R4 | share get owner_id only? | **held** |
| JP-R5 | putItemContents share_id query residual without checkIfAllowed? | **not checked this package** (commented call in source) |

Live residual: researcher-owned loopback only.