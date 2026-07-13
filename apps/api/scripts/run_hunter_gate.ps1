param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
)

$ErrorActionPreference = "Stop"
Set-Location $RepoRoot

$base = Join-Path $RepoRoot "apps\api\.pytest-tmp"
if (-not (Test-Path $base)) {
  New-Item -ItemType Directory -Force -Path $base | Out-Null
}
$env:TEMP = $base
$env:TMP = $base
$python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
  throw "Missing venv python: $python"
}

$targets = @(
  "apps/api/tests/test_scope_guard.py",
  "apps/api/tests/test_scope_guard_api.py",
  "apps/api/tests/test_candidate_hunter_loop.py",
  "apps/api/tests/test_candidate_hunter_hard_cases.py",
  "apps/api/tests/test_candidate_hunter_evidence.py",
  "apps/api/tests/test_cross_source_candidate_generator.py",
  "apps/api/tests/test_candidate_hunter_release_benchmark.py",
  "apps/api/tests/test_candidate_hunter_release_fixtures.py",
  "apps/api/tests/test_candidate_hunter_release_runner.py",
  "apps/api/tests/test_authorized_lab_package.py"
)

Write-Host "Running Candidate Hunter gate..."
& $python -m pytest @targets -q --tb=line --basetemp (Join-Path $base "gate")
exit $LASTEXITCODE
