# Residual checklist — my-gh-bookstack (optional)

Static package trial is expected **refute** (guards present). Residual only if researcher runs owned instance.

| ID | Question | Static status |
| --- | --- | --- |
| BS-R1 | Does page read use visibility-scoped lookup (not bare find by id)? | **held** — findVisibleByIdOrFail + scopes('visible') |
| BS-R2 | Do update/delete require ownable permission after visible load? | **held** — PageUpdate / PageDelete checkOwnablePermission |
| BS-R3 | Are drafts hidden from non-creators? | **held** — restrictDraftsOnPageQuery in Page::scopeVisible |
| BS-R4 | Does invisible page fail closed (404 not body)? | **held** — NotFoundException on null |
| BS-R5 | Export/API siblings also visibility gated? | **not checked this package** (optional follow-up) |

Live residual: researcher-owned loopback only; do not target third-party BookStack hosts.