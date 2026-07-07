# Bounty Mythos-Lite

Bounty Mythos-Lite is an authorized autonomous vulnerability research system for lawful bug bounty work. It centers on campaign-driven research: policy parsing, Scope Guard checks, target modeling, hypothesis generation, refutation, non-destructive validation planning, evidence review, report drafts, and advisory learning loops.

It deliberately does not perform public-target scanning, exploit execution, destructive validation, credential attacks, real-user data collection, or automatic bounty submission.

## Product Direction

The long-term product target follows `私人 AI 漏洞研究系统最终方案.md`. The short working reference is `docs/product/north-star.md`.

The current implementation priority is A+B Autonomous Candidate Hunter: combine authorized policy/scope/API/HAR artifacts with authorized local code to produce a small set of high-quality vulnerability candidates, each with affected endpoint, affected code path, evidence needs, refutation questions, safe validation plan, and submission-blocked report readiness.

## Structure

```text
apps/
  api/      FastAPI backend, Celery worker, LLM provider registry
  web/      Next.js dashboard shell
infra/      Docker Compose
docs/       Design specs and project notes
```

## Recommended Startup

The recommended research workflow is terminal-first. There is no installed
global `aegis` command yet, so run the CLI from `apps/api` with
`python -m app`. The older `python -m app.cli` form is still supported.

Install backend dependencies first:

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

All of these CLI paths stay inside the project safety boundary: no public-target
scanning, no destructive validation, no credential collection, no automatic
approval, and no automatic report submission.

## Local Services

Copy `.env.example` to `.env` before running services that need environment variables.

```powershell
docker compose -f infra/docker-compose.yml up --build
```

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
