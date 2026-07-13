# my-h1-gitlab-own-instance

Authorized local package for HackerOne **gitlab** / Own Instance, backed by public CE-style source acquisition.

## Trial
```powershell
cd "C:\Users\Administrator\Desktop\Bounty Mythos-Lite"
$base = "apps\api\.pytest-tmp"; $env:TEMP=$base; $env:TMP=$base; $env:PYTHONPATH="apps\api"
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root "authorized_packages\my-h1-gitlab" --md-name "hunter-ab-my-h1-gitlab-trial.md" --json-name "hunter-ab-my-h1-gitlab-trial.json"
```

See PROVENANCE.md and STATUS.md.
