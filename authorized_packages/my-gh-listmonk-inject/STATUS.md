# my-gh-listmonk-inject status

## Acquisition push result
- Source: public GitHub knadh/listmonk (no H1 API required)
- Version pin: **v6.2.0** + static excerpts (makeSearchString + QueryCampaigns + bound $4)
- Faithful injection model: makeSearchString before run_sql
- Trial: **2/0 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:makeSearchString
- Residual LM-INJ-R1..R6: static held / documented

## Product read
Fourth **non-authz (injection)** GitHub package:
- Exercises SQL/query sinks (`run_sql`) and `injection_validation_check`
- Hunter root_cause: `missing_injection_validation`
- Complements path package `my-gh-listmonk-path` and authz package `my-gh-listmonk`
- Not a bounty auto-submit package

Updated: 2026-07-12T18:45:00Z
