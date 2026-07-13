# Residual version-diff checklist (Node.js core permission/fs)

Use this only on a researcher-controlled Node build/source checkout or installed runtime. No live attacks.

Companion: `docs/hunter-ab-residual-runbook.md` ?5
Facts: `SOURCE_FACTS.md`
Filled report: `docs/hunter-ab-local-env-and-node-residual.md`

## Version pin

- Local product version / commit: **Node.js v24.15.0** (runtime binary; no full core source tree on disk)
- Install type: official Windows nodejs install (`C:\Program Files\nodejs\node.exe`)
- Date checked: 2026-07-12

## Control matrix

| ID | Control point | Status (present/changed/missing/alternate) | Notes |
| --- | --- | --- | --- |
| NJ-1 | Permission API isEnabled/has/drop | present (partial) | `process.permission.has` present under `--permission`; `drop` not on observed keys |
| NJ-2 | path reads deny without fs.read grant | present | denied sibling path -> ERR_ACCESS_DENIED |
| NJ-3 | write-class require fs.write | present | denied path write -> ERR_ACCESS_DENIED |
| NJ-4 | symlink requires full fs | present | local smoke: symlink denied without full fs read+write; target outside grant denied |
| NJ-5 | separate read/write grant trees | present | has(fs.read/write) true only for allowed path |
| NJ-6 | SECURITY non-vuln / opt-in boundaries | present | without flag, model inactive; expected |

## Residual hypotheses (if any)

_None from this runtime smoke. Controls hold on checked rows including NJ-4 symlink behavioral gate._

## Classification discipline

- Operator-enabled flags and intentional grant lists are not automatic core vulns.
- Symlink/realpath into an already-allowed path is usually intended.
- Prefer reports that show core policy violation under the published threat model with open-source reproduction.

## Safety

- [x] local-only target
- [x] no real user private data collected
- [x] no destructive tests
- [x] report submission blocked

## Result

- [x] controls still hold (zero residual)
- [ ] residual hypothesis written for human review
