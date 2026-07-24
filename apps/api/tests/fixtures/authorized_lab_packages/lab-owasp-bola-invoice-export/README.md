# lab-owasp-bola-invoice-export

Educational authorized lab package for G13 package-root trials.

## Provenance

- Kind: local educational derivation (not a third-party product dump)
- Pattern: OWASP API Security Top 10 A01 Broken Object Level Authorization
- Adaptation: single-file TypeScript Express-style snapshot shaped for A+B package contract
- No production code, no live host, no real user records

Why not a full public repo (Juice Shop, crAPI, etc.)?
1. The A+B mapper accepts supported local source surfaces; this fixture uses a TypeScript Express-style snapshot and known sinks.
2. Fixture sanitizer rejects external URLs and secret-shaped text.
3. Project safety rules forbid treating public targets as scan targets.

## Expected research outcome

Retain a single authorization candidate on unguarded `export_file` for
`GET /local/invoices/m8r3/:invoice_id` via `export_invoice`.

## Run

```powershell
$base = "apps\api\.pytest-tmp"; $env:TEMP=$base; $env:TMP=$base; $env:PYTHONPATH="apps\api"
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root apps/api/tests/fixtures/authorized_lab_packages/lab-owasp-bola-invoice-export
```
