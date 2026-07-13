# my-gh-mealie-inject status

## Acquisition push result
- Source: public GitHub mealie-recipes/mealie (no H1 API required)
- Version pin: **v3.20.1** + static excerpts (SearchFilter + QueryFilterBuilder + page_all)
- Faithful injection model: makeSearchString / sql_sanitize before run_sql
- Trial: **2/0 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:makeSearchString + code:code.ts:sql_sanitize
- Residual ME-INJ-R1..R6: static held / documented

## Product read
Second **non-authz (injection)** GitHub package (diversity beyond listmonk-inject):
- Exercises SQL/query sinks (
un_sql) and injection_validation_check
- Hunter root_cause: missing_injection_validation
- Complements authz package my-gh-mealie and mass package my-gh-mealie-mass
- Not a bounty auto-submit package

Updated: 2026-07-12T20:46:57Z
