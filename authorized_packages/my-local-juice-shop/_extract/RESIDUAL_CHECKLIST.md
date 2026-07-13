# RESIDUAL_CHECKLIST — my-local-juice-shop

| ID | Expected | Observe | Unexpected residual? |
| --- | --- | --- | --- |
| JS-BASKET-1 | load by id | present in basket.ts | no (intentional) |
| JS-BASKET-2 | no ownership deny before response | present | no (intentional) |
| JS-BASKET-3 | challenge detects but does not block | present | no (intentional) |

Fill date: 2026-07-12
Method: static review of public MIT sources + local lab authorization class.
Result: **0 unexpected residual**; package expects retain on unguarded basket export model.