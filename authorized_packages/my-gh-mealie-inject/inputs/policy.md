Authorized GitHub-sourced package my-gh-mealie-recipe-inject-lab.

Source: public mealie-recipes/mealie repository on GitHub plus optional researcher-owned self-hosted Mealie.
Security contact for real vulnerabilities: follow SECURITY.md private vulnerability reporting.
Review-only evidence in this package; live validation and report submission are blocked by default.
Do not store real Authorization headers, tokens, cookies, or private user data in package inputs.
Static modeling of recipe search / query-filter sanitization only (SearchFilter normalize + QueryFilterBuilder parameterized ORM before run_sql).
Out of scope: automated scanners on production infrastructure without sandbox, DoS, social engineering, live destructive SQL.
