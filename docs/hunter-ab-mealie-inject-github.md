# Mealie recipe search inject package (injection family)

Updated: 2026-07-12T20:46:57Z

Package: uthorized_packages/my-gh-mealie-inject
Package id: my-gh-mealie-recipe-inject-lab
Upstream: mealie-recipes/mealie **v3.20.1**
Risk family: **injection**
Expected disposition: **refute**
Trial: **2/0 refuted** (docs/hunter-ab-mealie-inject-trial.{json,md})

## What this proves
- Second injection GitHub package (diversity beyond listmonk-inject).
- Engine maps SQL/query sinks (
un_sql) to missing_injection_validation.
- Controls makeSearchString / sql_sanitize (plus regex_full_text) refute via injection_validation_check.
- Complements authz package my-gh-mealie and mass package my-gh-mealie-mass without pure authz spam.

## Faithful upstream model
- SearchFilter._normalize_search / _build_search_list: punctuation strip + token list
- RepositoryGeneric.add_search_to_query -> SearchFilter.filter_query_by_search (ORM binds)
- QueryFilterBuilder.filter_query: validated attribute/value as SQLAlchemy column binds
- No string-concat user SQL clauses on the modeled search path

## Residual
See _extract/RESIDUAL_CHECKLIST.md ME-INJ-R1..R6.

## Do not
- Attack third-party Mealie hosts
- Treat refute package as confirmed vuln
- Store secrets / real user data
