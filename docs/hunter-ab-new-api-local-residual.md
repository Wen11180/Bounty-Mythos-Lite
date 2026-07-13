# A+B Residual — local new-api (non-teaching)

Updated: 2026-07-12T08:42:44Z

Package: `authorized_packages/my-local-new-api`  
Trial: `docs/hunter-ab-my-local-new-api-trial.md`  
Facts: `authorized_packages/my-local-new-api/_extract/SOURCE_FACTS.md`

## Authorization class

- Researcher-owned local self-hosted open-source app (`calciumion/new-api`)
- Loopback bind observed: `127.0.0.1:3001` (`/api/status` HTTP 200)
- Public controllers model expected ownership gates; not a multi-tenant SaaS attack package
- Live validation and report submission remain blocked

## Trial outcome

| Metric | Value |
| --- | --- |
| decisions | 3 |
| finals | 0 |
| dispositions | all **refuted** via `code:code.ts:owner_id_filter` |
| safety_failures | empty |
| expected_disposition | refute |

Sanitizer note: package inputs avoid secret-shaped patterns (`token=`, `token:`, bearer, cookies, real keys). Modeling uses access-key object paths faithful to GetTokenByIds / DeleteTokenById.

## Control points residual

| ID | Control | Local / source observation | Residual |
| --- | --- | --- | --- |
| NA-1 | UserAuth sets user id into context | public auth.go; modeled via current_user | present |
| NA-2 | Get path uses GetTokenByIds(id, userId) | public token.go; modeled verify_access_key_read_access + owner_id !== user.id | present / 0 residual |
| NA-3 | Update reloads via GetTokenByIds before write | public token.go; modeled verify_access_key_update_access | present / 0 residual |
| NA-4 | Delete uses DeleteTokenById(id, userId) | public token.go; modeled verify_access_key_delete_access | present / 0 residual |
| NA-5 | List uses GetAllUserTokens(userId) | documented in SOURCE_FACTS; not required for this trial surface | source-present (list surface out of package routes) |
| NA-6 | Admin surfaces AdminAuth | separate role gate; not modeled as unguarded user path | not in trial surface |

## Residual questions (local only)

1. Does the installed image still call GetTokenByIds on Get/Update?
2. Is there an alternate admin/export path that skips user-scoped lookup?
3. Did a version bump reorder middleware so UserAuth is optional on any write path?
4. Any channel/relay object routes with weaker ownership than access-key paths?

## Do not

- Invent unguarded inputs contradicting public source
- Treat this package as a HackerOne submission
- Attack internet-facing new-api deployments
- Store real API secrets in package inputs
