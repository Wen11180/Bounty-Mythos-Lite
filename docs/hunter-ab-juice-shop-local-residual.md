# A+B Local Residual — OWASP Juice Shop

Date: 2026-07-12
Package: `authorized_packages/my-local-juice-shop`
Method: static review of public MIT sources under `_upstream/`; hunter trial on modeled excerpt.
No live exploit payloads against third-party hosts.

## Version / auth pin

| Field | Value |
| --- | --- |
| Project | juice-shop/juice-shop (MIT) |
| Local container | `juice-shop` present on host |
| Auth class | researcher-owned intentionally vulnerable lab |
| Primary source | `routes/basket.ts` `retrieveBasket` |

## Control matrix

| ID | Observation | Unexpected residual? |
| --- | --- | --- |
| JS-BASKET-1 | load basket by id | no (intentional) |
| JS-BASKET-2 | response without ownership deny | no (intentional) |
| JS-BASKET-3 | challenge detect != block | no (intentional) |

## Hunter trial link

- Scorecard: `docs/hunter-ab-my-local-juice-shop-trial.md`
- Result: **1 retained** final; safety fail-closed
- Read: second local-lab retain path works

## Note

Docker CLI hung during residual turn; package modeling does not depend on live container RPC.