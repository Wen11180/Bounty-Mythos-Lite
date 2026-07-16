# Commercial delivery runbook

**Claim scope:** commercial packaging + lab/live-infra readiness.

**Not claimed:** live bounty TOP1, XBOW ranking, remote auto-attack, auto-submission.

Updated: 2026-07-16

## What ships

Mythos-Lite is a **lawful, falsify-first vulnerability research factory**:

1. Authorized policy/API/HAR/local code intake under Scope Guard
2. Attack-surface modeling + static/semantic candidates
3. Refutation cards before validation planning
4. Human approval for validation, evidence promotion, and report drafts
5. **No** auto public attack, **no** auto-submission, **no** raw secret retention

## Anti auto-exploit narrative (customer-facing)

Do **not** sell “fully autonomous exploitation.” Sell:

> A senior researcher’s forced-refutation assembly line — high-precision candidates, kill evidence for false positives, explicit evidence gaps, submission blocked until humans decide.

| Competitor demo | Mythos commercial value |
| --- | --- |
| Autonomous exploit chains | Auditable Falsification Cards |
| High-volume noise | Review-ready precision |
| Live attack theater | Scope Guard + human gates |
| Rankings from unattended runs | Authorized redacted track-record packages |

## Pre-delivery checklist

```powershell
cd apps/api
$env:PYTHONPATH = (Get-Location).Path
python -m app lab-leadership-rollup --out tmp/lab-leadership.json
python -m app multilang-production-breadth --out tmp/multilang-breadth.json
python -m app human-hour-calibration --out tmp/human-hour.json
python -m app authorized-live-calibration --out tmp/live.json
python -m app delivery-readiness --out tmp/delivery.json
python -m app market-leadership-scoreboard --out tmp/market.json
python -m app commercial-delivery-bundle --out-dir tmp/commercial-bundle --human-allow-write
python -m app export-research-track-record --demo --out tmp/export-demo-manifest.json
```

Expect:

- `delivery-readiness.passed == true` (lab + live infra + breadth)
- `remaining_for_full_market_leadership` lists only **real-data** gaps until real packages attach
- `execution_allowed`, `report_submission_allowed`, `auto_attack_allowed` always false


## One-command commercial bundle

Produces customer-facing artifacts without unlocking attack/submit:

```powershell
python -m app commercial-delivery-bundle `
  --out-dir tmp/commercial-bundle `
  --human-allow-write
```

Artifacts under `tmp/commercial-bundle/`:

| File | Purpose |
| --- | --- |
| `manifest.json` | Bundle pass/fail + closed/remaining gaps |
| `customer_brief.md` | Sales/customer-facing brief (anti-auto-exploit) |
| `market_scoreboard.json` | Honest market gap scoreboard |
| `anti_auto_exploit.json` | Checkable anti-auto-exploit proof |
| `safety_invariants.json` | Locked safety gates proof |
| `lab_summary.json` / `live_summary.json` / `breadth_summary.json` | Gate summaries |

Closed without real packages: multilang breadth, commercial packaging, anti-auto-exploit narrative.

Still remaining until real attach: wall-clock logs + live valid report outcomes.

## Attach real packages (closes market gaps)

### Live wall-clock + valid outcomes

Template: `apps/api/app/intelligence_benchmark/fixtures/templates/authorized_wall_clock_and_outcomes.template.json`

```powershell
python -m app authorized-live-calibration --out tmp/live-real.json --log path/to/authorized_redacted_real.json
python -m app delivery-readiness --out tmp/delivery.json --live-log path/to/authorized_redacted_real.json
```

### Human-hour wall-clock (alternative path for wall-clock gap)

Template: `apps/api/app/intelligence_benchmark/fixtures/templates/authorized_human_hour_wall_clock.template.json`

```powershell
python -m app human-hour-calibration --out tmp/hh-real.json --log path/to/authorized_hh_real.json
python -m app delivery-readiness --out tmp/delivery.json --log path/to/authorized_hh_real.json
```


### Prepare + drop-dir auto-attach

```powershell
# Scaffold a capture-ready package root
python -m app prepare-research-session-package --package-root path/to/pkg --human-allow-write

# After authorized research, capture and publish to drop dir
python -m app capture-research-session-track-record `
  --package-root path/to/pkg `
  --program-authorization-id AUTH-REF-001 `
  --declare-real-package `
  --human-allow-export-write `
  --out-dir tmp/capture-real `
  --publish-drop-dir

# Auto-attach from authorized_track_records/ (or env paths)
python -m app market-leadership-scoreboard --out tmp/market.json
python -m app delivery-readiness --out tmp/delivery.json
```

Env overrides: `MYTHOS_LIVE_TRACK_RECORD`, `MYTHOS_HUMAN_HOUR_TRACK_RECORD`, `MYTHOS_TRACK_RECORD_DIR`.

### Export from research session (preferred capture path)

Prefer capturing from an authorized research package root rather than hand-writing packages.

**One-command capture (package root):** discovers `inputs/session_notes.json`,
`inputs/wall_clock_runner.json` / `_export/wall_clock_multi_hour_runner/**`, and residual
approvals under the package root.

```powershell
# Synthetic dry-run from package root (never flips has_real_*)
python -m app capture-research-session-track-record `
  --package-root path/to/research-package `
  --out-dir tmp/capture-demo `
  --human-allow-export-write `
  --out tmp/capture-demo/manifest.json

# Real authorized redacted package (requires explicit declare + auth ref)
python -m app capture-research-session-track-record `
  --package-root path/to/authorized-research-package `
  --program-handle my-authorized-program `
  --program-authorization-id AUTH-REF-001 `
  --declare-real-package `
  --human-allow-export-write `
  --out-dir tmp/capture-real `
  --out tmp/capture-real/manifest.json

python -m app delivery-readiness --out tmp/delivery.json --live-log tmp/capture-real/authorized_live_outcomes.export.json
```

**Explicit artifact export** (when files are not under a package root):

```powershell
# Synthetic dry-run (never flips has_real_*)
python -m app export-research-track-record --demo --out-dir tmp/export-demo --human-allow-export-write --out tmp/export-demo/manifest.json

# Real authorized redacted package (requires explicit declare + auth ref)
python -m app export-research-track-record `
  --session-notes path/to/session_notes.json `
  --approvals path/to/residual_approvals.json `
  --wall-clock-json path/to/wall_clock_runner.json `
  --program-handle my-authorized-program `
  --program-authorization-id AUTH-REF-001 `
  --declare-real-package `
  --human-allow-export-write `
  --out-dir tmp/export-real `
  --out tmp/export-real/manifest.json

python -m app delivery-readiness --out tmp/delivery.json --live-log tmp/export-real/authorized_live_outcomes.export.json
```

Inputs: residual human-review decisions, session notes, optional wall-clock multi-hour runner ledger.
Outputs: live outcomes package + human-hour package compatible with calibration gates.
Still never auto-attacks or auto-submits.

### Rules

| Requirement | Value |
| --- | --- |
| `source_kind` | `authorized_redacted_real` or `authorized_program_redacted` |
| `program_authorization_id` | required |
| secrets/tokens/cookies | never |
| synthetic fixtures | never flip `has_real_*` |
| auto-submit | never |

## Lab leadership already closed

- A+B falsify corpus (90 scenarios, Rust/Scala included)
- Multilang production breadth beyond held-outs (language×pattern matrix)
- Human-hour calibration infrastructure (synthetic + attach protocol)
- Live track-record infrastructure (synthetic + attach protocol)

## Still required for full market leadership claims

1. Real authorized program wall-clock logs (live or human-hour real package)
2. Real human-confirmed live valid-report outcomes

Until those attach, market messaging stays:

> Lab quality leadership + lawful infra ready; live track record pending authorized packages.
