# Package template

Copy this directory to a new folder (do not edit the smoke package in place).

1. Replace `package_id` and route/code with authorized local artifacts.
2. Keep safety flags false for real-user-data/secrets.
3. Keep `allowed_repos: ["${STAGED_CODE_ROOT}"]`.
4. Code must be TypeScript (`.ts`) for the current A+B mapper.
5. Avoid literal text `real user data`, bearer tokens, cookies, or external http(s) URLs in package files.
6. Run:

```powershell
$base = "apps\api\.pytest-tmp"; $env:TEMP=$base; $env:TMP=$base; $env:PYTHONPATH="apps\api"
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root PATH\TO\YOUR\PACKAGE
```

Gold (`gold.json`) is optional. Without gold, the trial still emits retained cards for H1-H7.
