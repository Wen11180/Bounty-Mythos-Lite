# Bounty Mythos-Lite Project Initialization Design

## Goal

Initialize Bounty Mythos-Lite as a full engineering foundation for a bug bounty research assistant. The first milestone is a runnable scaffold, not a working vulnerability automation system.

Success means the repository has a clear monorepo layout, a Next.js frontend, a FastAPI backend, a Celery worker, Redis and PostgreSQL infrastructure, basic tests, and a unified LLM provider layer for OpenAI, Claude, and DeepSeek.

## Scope

Build the project foundation:

- Next.js and Tailwind frontend under `apps/web`.
- FastAPI backend under `apps/api`.
- Celery worker connected to Redis.
- PostgreSQL and Redis through Docker Compose.
- Basic API schemas for programs, findings, reports, validation state, and LLM requests.
- Mock data for initial product screens.
- Tests for backend health and LLM provider routing.
- Frontend lint/build configuration.
- Environment templates for local development.

Do not build real public-target scanning, exploit execution, automatic report submission, destructive validation, or live agent workflows in this initialization step.

## Architecture

The repository uses a monorepo layout:

```text
apps/
  web/
  api/
infra/
docs/
```

The frontend talks only to the FastAPI backend. The backend owns database access, model calls, audit boundaries, and all future safety gates. Celery handles future long-running jobs such as policy parsing, artifact ingestion, hypothesis generation, report drafting, and validation planning.

## Frontend

The frontend starts as an app shell with the final product navigation:

- Dashboard
- Programs
- Assets
- API Model
- Business Flows
- Hypotheses
- Validation Plans
- Findings
- Reports
- Submissions
- Knowledge Base
- Settings / Policy Guard

The first screen should show operational metrics from the product notes: parsed programs, high-value candidates, report-ready findings, human confirmations, policy blocks, accepted rate, duplicate rate, informative/N/A rate, policy violations, and accepted bounty per human hour.

Pages can use mock data at initialization. They must not imply that live vulnerability discovery is already running.

## Backend

FastAPI provides:

- `GET /health`
- Program list/detail endpoints backed by in-memory sample data
- Finding list/detail endpoints backed by in-memory sample data
- Report draft endpoints backed by in-memory sample data
- LLM provider routing endpoint for internal testing

The backend models the core safety states:

- `candidate`
- `plausible`
- `policy_checked`
- `validation_plan_ready`
- `human_approved`
- `safely_validated`
- `refuted_or_confirmed`
- `report_ready`
- `human_submitted`
- `accepted`
- `duplicate`
- `informative`
- `na`
- `learned`

These states are data only at initialization. They do not trigger live validation.

## LLM Provider Layer

The backend includes a provider abstraction under `apps/api/app/llm/`:

- `base.py` defines a shared provider interface.
- `openai_provider.py` calls OpenAI.
- `claude_provider.py` calls Anthropic Claude.
- `deepseek_provider.py` calls DeepSeek.
- `registry.py` selects a provider by `provider` and `model`.

Secrets are loaded only from environment variables:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `DEEPSEEK_API_KEY`

Frontend code never receives these keys. Initialization includes mock tests for routing across all three providers, but does not require real keys or spend tokens.

The provider interface should support plain generation first. Structured generation can be added as an interface method if needed by report or invariant workflows, but the initial scaffold should avoid deep provider-specific abstractions until a real workflow needs them.

## Worker

Celery starts with one safe `ping` task that verifies worker and Redis connectivity. Future task modules can map to:

- policy parsing
- scope guard rule generation
- artifact ingestion
- API modeling
- invariant generation
- hypothesis generation
- validation planning
- refutation
- evidence assembly
- report drafting
- learning loop updates

No worker task performs real target interaction during initialization.

## Infrastructure

Docker Compose should run:

- `web`
- `api`
- `worker`
- `postgres`
- `redis`

The local development environment uses `.env.example` files and does not commit secrets.

## Safety Boundaries

Scope Guard and human approval are first-class concepts from the start. Initialization includes explicit schema fields for:

- scope status
- policy status
- allowed validation modes
- forbidden validation modes
- human approval required
- audit log references

The scaffold must not include automatic public-target attacks, high-frequency scanning, DoS tooling, credential stuffing, social engineering, real user data access, destructive testing, or automatic bounty submission.

## Testing

Backend verification:

- `pytest` passes.
- `/health` test passes.
- LLM provider registry test passes using mocks.

Frontend verification:

- package install succeeds.
- lint or build command succeeds, depending on the generated Next.js setup.

Infrastructure verification:

- `docker compose config` succeeds.
- `docker compose up` can start the local services after dependencies are installed or images are built.

## Tradeoffs

This initializes the full engineering foundation instead of a smaller prototype. The benefit is that future backend, worker, and infrastructure work has a stable home from day one. The cost is more initial files and dependencies.

The LLM provider layer is intentionally thin. A large abstraction would be premature before real prompt workflows exist, but direct provider calls scattered through business modules would become hard to maintain. A small registry and shared interface is the simplest middle path.

## Out Of Scope

- Real vulnerability discovery.
- Live validation against public programs.
- Browser automation against third-party targets.
- Model prompt quality tuning.
- Full database migrations and production deployment hardening.
- Authentication and user management.
- Secret manager integration beyond environment-variable examples.
