# Mythos 5 Audit

Date: 2026-07-06

This audit checks the current tree against the product-level Mythos-Lite definition of done in `docs/product/autonomous-implementation-blueprint.md` and `docs/product/requirements-and-features.md`.

## Verification Snapshot

- API: `python -m pytest` in `apps/api` -> 299 passed, 1 warning.
- Web tests: `npm test` in `apps/web` -> 100 passed.
- Web lint: `npm run lint` in `apps/web` -> passed.
- Web build: `npm run build` in `apps/web` -> passed.
- Workspace whitespace: `git diff --check` -> passed with line-ending warnings only.
- Compose config: `docker compose -f infra/docker-compose.yml config --quiet` -> passed.

## Requirement Matrix

| Requirement | Current evidence | Status |
| --- | --- | --- |
| Create an authorized research campaign. | `apps/api/tests/test_campaign_api.py` covers `POST /mythos/campaigns`, list, start, pause, and resume. `apps/web/lib/campaigns-data.test.ts` verifies the `/campaigns` Launchpad uses `launchAuthorizedCampaign`. | Proven for API and web UI. |
| Provide scope, policy, artifacts, local code, allowed tools, budgets, and autonomy level. | Campaign create request covers policy, scope status, allowed tools, budget, and autonomy. The web Launchpad exposes policy, asset, allowed tools, autonomy, target class, and budget inputs. Artifact repository and worker tests cover authorized artifacts and local code mapping. | Proven across API and UI paths. |
| Autonomously run safe read-only and local/static research tasks. | Orchestrator and worker tests cover dispatch gates, codebase mapping, static scanner records, hypothesis generation, report preview, and approval-blocked validation records. | Proven. |
| See agent runs, blockers, approvals, stop reasons, and budget usage. | Campaign control center API and web mapper tests expose tasks, agent runs, approvals, pipeline stages, blocked reasons, safe next action, and budget labels. | Proven. |
| Review hypotheses, exploit-chain reasoning, refutation decisions, and validation plans. | Worker tests assert non-executable exploit-chain summaries, refutation questions, and approval-required validation plans; web tests cover hypothesis board and task review pages. | Proven. |
| Approve narrow validation batches where allowed. | Approval record API and validation preflight tests cover durable approvals, expiry, terminal decisions, plan digest matching, and approval budget gates. | Proven. |
| Review redacted evidence and claim quality. | Evidence review, report preview, validation workspace, and artifact repository tests cover redaction, provenance, quality/readiness, and report-chain blockers. | Proven. |
| Generate submission-blocked report drafts. | API and web tests assert report drafts remain gated and `submission_blocked` stays visible. | Proven. |
| Feed outcomes into advisory learning memory. | Mythos Brain and learning outcome tests cover advisory learning, evidence quality, learning refs, and safety-gate suppression. | Proven. |
| Preserve safety boundaries: no public-target attack automation, no destructive validation, no real user data, no raw secrets/tokens/cookies, no automatic submission. | API and web tests repeatedly inject token/cookie/PII-shaped values and assert redaction or blocked gates; UI tests assert no validation execution, approval, pause/resume, or report submission entrypoints. | Proven for tested paths. |

## UI Control Surface

The backend exposes create/start/pause/resume APIs. The web console now exposes only a narrow `Authorized Campaign Launchpad` that creates an authorized campaign and starts the safe campaign loop. It does not expose validation execution, approval decision, pause/resume, or report submission controls.

This closes the previous API-only campaign creation gap while preserving the operator console's review-first posture. Higher-risk controls should remain separate review workflows with explicit Scope Guard, approval, redaction, and report-submission gates.
