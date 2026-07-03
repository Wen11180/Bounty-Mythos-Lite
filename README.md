# Bounty Mythos-Lite

Bounty Mythos-Lite is a bug bounty research assistant scaffold. It starts as a safe engineering foundation for program policy parsing, scope guarding, hypothesis generation, validation planning, evidence building, reporting, and learning loops.

This initialization deliberately does not perform public-target scanning, exploit execution, destructive validation, or automatic bounty submission.

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

Backend tests:

```powershell
cd apps/api
python -m pytest
```

Frontend build:

```powershell
cd apps/web
npm run build
```
