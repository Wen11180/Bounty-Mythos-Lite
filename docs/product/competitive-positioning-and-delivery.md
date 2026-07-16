# Competitive positioning and commercial delivery

**Claim scope:** product positioning + lab/live-infra readiness only.

**Not claimed:** live bounty TOP1, XBOW ranking, remote auto-attack, auto-submission.

Updated: 2026-07-16

## Lead with (honest advantages)

1. **Falsify-first research factory** — every terminal decision carries an auditable Falsification Card (retain / refute / suppress / needs_evidence / dedupe / rank).
2. **Object-ownership semantics** — distinguishes real ownership controls from login-only, role-only, status-only, guard-after-sink, spoofable principals, and wrong-object checks.
3. **A+B lawful pipeline** — policy/scope/API/HAR + authorized local code under Scope Guard and human gates.
4. **Multi-language ownership held-outs** — Python, TypeScript, Java, Go, Rails, C#, PHP, Kotlin, **Rust**, **Scala** ownership refute + invalid-control retain paths in the A+B leadership corpus (**90 scenarios**).
5. **Production-shaped multilang breadth matrix** — language×pattern coverage beyond single held-out spot checks: ownership + high-signal gap families (SSRF / path / injection / mass-assign refute+retain) via `multilang-production-breadth`.
6. **Safety as product** — no auto public attack, no raw secrets, no auto report submission.

## Lagging vs market (and how we close)

| Gap | Competitor narrative | Mythos close path |
| --- | --- | --- |
| Live track record | “We found real bugs on live programs” | `authorized-live-calibration` + redacted real package protocol only |
| Production multi-lang SAST breadth | CodeQL/Semgrep rule ecosystems | **Lab breadth gate can pass**; still not a full commercial SAST claim |
| Real human-hour wall-clock | Internal research ops metrics | Same export path writes HH package; synthetic fixtures stay false |
| Auto-exploit demos | XBOW-style autonomous exploit | **Intentional non-goal** — reframe as quality/audit advantage |
| Commercial packaging | One-click SaaS | **`commercial-delivery-bundle`** + `delivery-readiness` + runbooks |

## Anti auto-exploit narrative (use this)

Do **not** compete on “fully autonomous exploitation.” Compete on:

> **A senior researcher’s forced-refutation assembly line** — high-precision candidates, kill evidence for FPs, explicit evidence gaps, submission blocked until humans decide.

Auto-exploit systems maximize attack surface throughput and demo drama.

Mythos-Lite maximizes **review-ready precision, auditability, and legal safety**.

## Delivery commands

```powershell
cd apps/api
$env:PYTHONPATH = (Get-Location).Path
python -m app ab-leadership-gate --out tmp/ab-leadership.json
python -m app multilang-production-breadth --out tmp/multilang-breadth.json
python -m app lab-leadership-rollup --out tmp/lab-leadership.json
python -m app human-hour-calibration --out tmp/human-hour-calibration.json --log app/intelligence_benchmark/fixtures/redacted_review_logs.json
python -m app authorized-live-calibration --out tmp/live-calibration.json
python -m app delivery-readiness --out tmp/delivery-readiness.json
python -m app market-leadership-scoreboard --out tmp/market-leadership.json
python -m app commercial-delivery-bundle --out-dir tmp/commercial-bundle --human-allow-write
python -m app export-research-track-record --demo --out tmp/export-demo-manifest.json
```

## What “full market leadership” still requires

1. Real authorized program wall-clock review logs (redacted).
2. Real human-confirmed live valid/FP outcomes (still no auto-submit).
3. ~~Broader production multi-language coverage beyond leadership held-outs~~ — **lab gate closed** via language×pattern matrix (`beyond_held_out`); still **not** a full commercial multi-language SAST product claim.
4. ~~Customer-facing packaging without weakening safety gates~~ — **closed** via `commercial-delivery-bundle` + packaging/anti-auto-exploit proofs (still no live TOP1 claim).

Lab 90/90 + multilang breadth + delivery-readiness pass is **necessary, not sufficient** for live TOP1 claims.

## Latest lab leadership wave (held-out multilang + breadth)

Status: **lab leadership infrastructure expanded**; full market TOP1 is **not** claimed.

| Area | Status | Evidence |
|------|--------|----------|
| A+B falsify corpus | **90 scenarios** | `ab-leadership-gate` |
| Kotlin Spring ownership | held-out refute + role-only retain | `refute_kotlin_ownership`, `retain_kotlin_role_only` |
| C# service-layer ownership | held-out refute | `refute_csharp_service_layer_ownership` |
| PHP controller ownership | held-out refute | `refute_php_controller_ownership` |
| Rust Axum ownership | held-out refute + role-only retain | `refute_rust_ownership`, `retain_rust_role_only` |
| Scala Spring ownership | held-out refute + role-only retain | `refute_scala_ownership`, `retain_scala_role_only` |
| Multilang production breadth | language×pattern matrix beyond held-outs | `multilang-production-breadth` (`beyond_held_out=true`) |
| Human-hour multilang packages | java/go/rails/ts/kotlin/csharp/php/rust/scala | `human-hour-calibration` |
| Live track-record infra | schema + redaction + real-package attach protocol | `authorized-live-calibration` |
| Auto-exploit / auto-submit | **intentional non-goal** | safety gates always false |
| Commercial delivery bundle | customer brief + scoreboard + safety proof | `commercial-delivery-bundle` |
| Anti-auto-exploit proof | checkable narrative gate | `anti_auto_exploit_narrative` closed on scoreboard |

### Still required for full market leadership

1. **Real authorized program wall-clock logs** (not synthetic fixtures).
2. **Real live valid-report outcomes** (human-confirmed accepted/valid reports under authorization).

`delivery-readiness` drops remaining gaps **only** when:

- breadth: `beyond_held_out` and gate passed
- real wall-clock / valid outcomes: `track_record_summary.has_real_*` true from an authorized redacted real package

### Real package attach protocol

Preferred capture: `capture-research-session-track-record --package-root ...` (discovers session notes / wall-clock / residual approvals), or `export-research-track-record` with explicit artifacts. Real flags require `--declare-real-package` + `--program-authorization-id`.

Drop-dir auto-attach: place exports in `apps/api/authorized_track_records/` or set `MYTHOS_LIVE_TRACK_RECORD` / `MYTHOS_HUMAN_HOUR_TRACK_RECORD`, then re-run `market-leadership-scoreboard` / `delivery-readiness`. Scaffold with `prepare-research-session-package`.

Live template: `apps/api/app/intelligence_benchmark/fixtures/templates/authorized_wall_clock_and_outcomes.template.json`

Human-hour template: `apps/api/app/intelligence_benchmark/fixtures/templates/authorized_human_hour_wall_clock.template.json`

Runbook: `docs/product/commercial-delivery-runbook.md`

Requirements for `has_real_*` flags:

- `source_kind` in `{authorized_redacted_real, authorized_program_redacted}`
- `program_authorization_id` present on package or entries
- wall-clock entries and/or `human_confirmed_valid` with `report_outcome_ref`
- synthetic committed fixture **never** flips real flags

### Positioning narrative (anti-auto-exploit)

Compete on **falsify-first quality**, not autonomous exploitation:

- Scope Guard and authorized artifact intake only
- Refutation cards before validation planning
- Human approval for validation, evidence promotion, and report submission
- Explicit refusal of auto-attack and auto-submission

Lab metrics must never be rephrased as live/XBOW ranking.
