# SOURCE_FACTS — local OWASP Juice Shop

Authorization class: researcher-owned intentionally vulnerable lab (Juice Shop).
Not a public production target. Not a bounty submission package.

## Control points from public upstream (basket.ts)

| ID | Observation |
| --- | --- |
| JS-BASKET-1 | `retrieveBasket` loads basket by `req.params.id` |
| JS-BASKET-2 | Response returns basket JSON without ownership deny gate |
| JS-BASKET-3 | Challenge solveIf detects cross-user access (`user.bid != id`) but does not block response |
| JS-FILE-1 | fileServer has extension allow-list before sendFile (different family) |

## Modeling choice

Hunter A+B scores authorization gaps on Express-shaped sinks without `verify_*_access`.
Package models JS-BASKET-1/2 as unguarded `export_file(basket_id)`.

## Residual

Intentional Juice Shop challenges only. Zero unexpected production residual.