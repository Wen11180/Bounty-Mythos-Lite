# SOURCE_FACTS — local new-api (Calcium-Ion/new-api)

Authorization class: researcher-owned self-hosted open-source app on loopback.
Not a public SaaS target. Not a bounty submission package unless a separate program scope exists.

## Local pin

- Observed service: HTTP 200 on 127.0.0.1:3001 (`/api/status`)
- Image class: calciumion/new-api
- Research mode: static modeling only; no live token enumeration

## Control points from public token.go / auth.go

| ID | Control | Observation |
| --- | --- | --- |
| NA-1 | UserAuth | middleware sets user id into context (`c.Set("id", ...)`) |
| NA-2 | GetToken | `userId := c.GetInt("id")` then `model.GetTokenByIds(id, userId)` |
| NA-3 | UpdateToken | reloads via `GetTokenByIds(token.Id, userId)` before update |
| NA-4 | DeleteToken | `model.DeleteTokenById(id, userId)` |
| NA-5 | GetAllTokens | `model.GetAllUserTokens(userId, ...)` user-scoped list |
| NA-6 | Admin surfaces | separate AdminAuth role gate (not modeled as unguarded user token path) |

## Research implication

Faithful token object paths are ownership-scoped. Naive missing-ownership candidates should **refute**.
Residual value is alternate routes, admin role confusion, or version drift — not inventing unguarded GetToken.