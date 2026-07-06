# Bounty Mythos-Lite

Bounty Mythos-Lite is an authorized autonomous vulnerability research system for lawful bug bounty work. It centers on campaign-driven research: policy parsing, Scope Guard checks, target modeling, hypothesis generation, refutation, non-destructive validation planning, evidence review, report drafts, and advisory learning loops.

It deliberately does not perform public-target scanning, exploit execution, destructive validation, credential attacks, real-user data collection, or automatic bounty submission.

## Structure

```text
apps/
  api/      FastAPI backend, Celery worker, LLM provider registry
  web/      Next.js dashboard shell
infra/      Docker Compose
docs/       Design specs and project notes
```

## Local Development

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
```

Docker Compose configuration check:

```powershell
docker compose -f infra/docker-compose.yml config --quiet
```

The API Docker image uses Python 3.12. Local development should use the pinned
`apps/api/requirements.txt` dependencies before running tests.
