# Bounty Mythos-Lite

Bounty Mythos-Lite is an SRC/HackerOne-first autonomous vulnerability discovery system for lawful bug bounty work. It automatically turns explicitly authorized program rules and research artifacts into a short list of high-quality vulnerability candidates, evidence requirements, safe validation plans, and submission-blocked report drafts.

It deliberately does not perform public-target scanning, exploit execution, destructive validation, credential attacks, real-user data collection, or automatic bounty submission.

## Product Direction

The active product direction is `docs/product/north-star.md`. `私人 AI 漏洞研究系统最终方案.md` is a long-term capability reference, not the current implementation target.

**Active direction: SRC/HackerOne autonomous high-quality vulnerability discovery.** The product should autonomously understand program rules and target materials, form and refute high-value hypotheses, and rank the small number of candidates that deserve human validation. It is not an unrestricted autonomous live-execution platform.

Given program policy, scope, API/HAR traffic, local code, and other operator-provided authorized material, Mythos-Lite should autonomously model the target, choose high-value attack surfaces, generate and refute vulnerability hypotheses, connect each candidate to traceable evidence, rank a short queue, prepare safe validation work, and draft submission-blocked reports for human review. Manual submission outcomes then improve future ranking.

Current implementation provides the safety, artifact, candidate, report-readiness, and review-loop foundation. The next implementation priorities are autonomous candidate-hunter depth, semantic coverage, impact calibration, duplicate avoidance, platform-style report quality, and outcome learning on chosen in-scope programs. Scheduling and Autopilot work should advance that discovery loop rather than become a separate product focus.


Preferred local software entrypoint: Mythos Studio. During development, run it from `apps/studio` after installing API and web dependencies. The Studio launcher opens the local `/studio` workspace without making the browser dashboard the primary experience. It defaults to inline safe read-only worker dispatch, so Redis/Celery is not required for the local desktop campaign loop.

While Studio is open, its local wake-up timer calls the same durable coordinator
used by the backend scheduler once per minute. The shared coordinator owns the
lease and cursor, advances at most one persisted research task per campaign
tick, and stops at scope, budget, evidence, or human-review gates. Closing
Studio stops only its local timer; a later launch resumes from the database
without replaying completed work.

### Public program rule intake

The Studio `/studio` workspace can register one public HTTPS bounty-policy URL and turn it into review-gated scope rules. Studio performs bounded, DNS-pinned acquisition; the browser UI never fetches the policy URL. First, changed, rejected, ambiguous, unsupported-language, missing-evidence, and stale snapshots remain non-authorizing until a human reviews the current digest. The feature never grants execution, validation, lease, scope-change, review-bypass, or report-submission authority.

Server-only Compose can review existing snapshots but has no network worker and must report `studio_required`. Authenticated/private pages, local rule-file import, credentials, HAR discovery, target scanning, validation execution, and automatic submission are outside this version. See [Public Program Rule Intake](docs/PROGRAM_RULE_INTAKE.md) for the operator runbook, release checklist, and verification commands.

## Structure

```text
apps/
  api/      FastAPI backend, Celery worker, LLM provider registry
  web/      Next.js dashboard shell
infra/      Docker Compose
docs/       Design specs and project notes
```

## Recommended Startup

The recommended research workflow is Mythos Studio first. The desktop launcher
starts the local API and Studio UI, waits for the local service to become ready,
chooses available local ports if the defaults are occupied, and opens the
`/studio` workspace in an app window.

```powershell
cd apps/api
python -m pip install -r requirements.txt
cd ../web
npm install
cd ../studio
npm install
npm start
```

Advanced automation can still use the CLI. There is no installed global `aegis`
command yet, so run the CLI from `apps/api` with `python -m app`. The older
`python -m app.cli` form is still supported.

For CLI use, install backend dependencies first:

```powershell
cd apps/api
python -m pip install -r requirements.txt
```

Create or reuse a scope file that allowlists only the local repository you are
authorized to inspect:

```yaml
allowed_repos:
  - C:/path/to/authorized-target
```

Run the V0 local source audit:

```powershell
python -m app scan `
  --repo C:/path/to/authorized-target `
  --scope C:/path/to/scope.yaml `
  --output source-audit.md `
  --findings-output findings.json `
  --audit-log audit-log.json
```

Run the Codex-style bounded agent loop:

```powershell
python -m app agent `
  --repo C:/path/to/authorized-target `
  --scope C:/path/to/scope.yaml `
  --goal "Run a bounded safe research loop" `
  --database-url sqlite:///mythos-agent.sqlite `
  --max-steps 6 `
  --receipt-output agent-receipt.json
```

After a run, ask the system what to do next and inspect the human gates:

```powershell
python -m app agent-next `
  --database-url sqlite:///mythos-agent.sqlite `
  --resume-from agent-receipt.json

python -m app agent-gates `
  --database-url sqlite:///mythos-agent.sqlite `
  --resume-from agent-receipt.json
```

Record human review notes without approving or executing validation:

```powershell
python -m app agent-review-note `
  --database-url sqlite:///mythos-agent.sqlite `
  --resume-from agent-receipt.json `
  --gate-ref approval:<id> `
  --reviewer lead_reviewer `
  --decision needs_evidence `
  --note "Need sanitized evidence before approval."
```

For a lightweight terminal chat wrapper:

```powershell
python -m app chat
```

Evaluate a saved Studio candidate response against a local A+B benchmark
expectation file:

```powershell
python -m app studio-eval `
  --candidates C:/path/to/studio-candidates.json `
  --expectations C:/path/to/studio-expectations.json `
  --output studio-eval-result.json
```

Generate a draft expectation template for human review before turning it into a
quality gate:

```powershell
python -m app studio-eval-template `
  --candidates C:/path/to/studio-candidates.json `
  --output studio-expectations-template.json
```

The Studio API also exposes `/mythos/studio/workspaces/benchmarks/template` and
`/mythos/studio/workspaces/benchmarks/run` for creating a reviewable template and
benchmarking a workspace run directly from the local app shell.

All of these CLI paths stay inside the project safety boundary: no public-target
scanning, no destructive validation, no credential collection, no automatic
approval, and no automatic report submission.

## Local Services

Copy `.env.example` to `.env` before running services that need environment variables.

```powershell
docker compose -f infra/docker-compose.yml up --build
```

Compose starts the API, Celery worker, and a `beat` scheduler. The scheduler
publishes the durable `autonomous_research.wakeup` task once per minute. Its
cursor and lease live in Postgres, and its local Celery schedule file is kept in
the `celery_beat_data` volume, so a container restart resumes from persisted
state. Only `running`, `in_scope`, `level_0_read_only` campaigns are considered;
each campaign still advances one read-only work item per tick. Campaigns in
review, validation handoff, blocked, paused, or terminal states are left alone.

Inspect the long-running path with:

```powershell
docker compose -f infra/docker-compose.yml logs -f beat worker
```

The wake-up mechanism cannot approve validation, promote a candidate, run a
remote lease, or submit a report. Those actions remain behind the existing
human-review gates.

Backend verification:

```powershell
cd apps/api
python -m pip install -r requirements.txt
python -m pytest
```

Frontend verification:

```powershell
cd apps/web
npm install
npm test
npm run lint
npm run build
npm run e2e
```

Docker Compose configuration check:

```powershell
docker compose -f infra/docker-compose.yml config --quiet
```

The API Docker image uses Python 3.12. Local development should use the pinned
`apps/api/requirements.txt` dependencies before running tests.
