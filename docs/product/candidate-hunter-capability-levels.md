# Candidate Hunter capability levels

The capability label is derived from evidence. A corpus manifest may request a
level, but it cannot grant that level to itself.

## Levels

| Level | Meaning | Evidence source |
| --- | --- | --- |
| `lab` | Synthetic, teaching, minimized, or otherwise laboratory cases | Local fixture tests |
| `benchmark` | Repository-isolated historical vulnerabilities with hidden oracle material and reproducible upstream history | Offline provenance gate |
| `field_proven` | Externally reviewed outcomes from authorized engagements | Separate human-reviewed outcome record |

The corpus gate proves offline provenance prerequisites only. A separate,
opt-in GitHub gate now binds public repositories, commits, and trees to the
declared upstream identity. Neither gate can grant `benchmark` until runtime
isolation is also verified across prompt, trace, output, cache, and logs. Both
always reject `field_proven` because fixtures cannot prove accepted reports or
bounty outcomes.

## Current status

The committed Candidate Hunter release suites remain **Lab**. Their metrics are
reported with:

```json
{
  "metric_scope": "lab",
  "capability_level": "lab",
  "benchmark_claim_allowed": false
}
```

The repository-history pilot contains five offline evidence-verified historical
cases from five repository lineages and five risk families:

- [`fastify/fast-uri` GHSA-q3j6-qgpj-74h6](https://github.com/fastify/fast-uri/security/advisories/GHSA-q3j6-qgpj-74h6);
- [`ljharb/shell-quote` GHSA-g4rg-993r-mgx7](https://github.com/advisories/GHSA-g4rg-993r-mgx7);
- [`unshiftio/url-parse` GHSA-hgjh-723h-mx2j](https://github.com/advisories/GHSA-hgjh-723h-mx2j);
- [`minimistjs/minimist` GHSA-vh95-rmgr-6w4m](https://github.com/advisories/GHSA-vh95-rmgr-6w4m);
- [`yahoo/serialize-javascript` GHSA-hxcc-f52p-wc94](https://github.com/advisories/GHSA-hxcc-f52p-wc94).

Each case has a full vulnerable tree, fixed tree, canonical binary diff,
evaluator-only structured root cause, and an offline Git bundle that proves the
fixed commit descends from the vulnerable commit. The corpus audit now reports
`historical_pilot.corpus_ready: true` only after at least five verified cases,
five repository lineages, four risk families, and one unique advisory event per
case are present. This is corpus readiness, not model evidence:

```json
{
  "historical_pilot": {
    "corpus_ready": true,
    "verified_cases": 5,
    "repository_lineages": 5,
    "risk_families": 5,
    "blind_model_evaluation_completed": false
  }
}
```

The local Git evidence is internally reproducible. The opt-in live gate can
upgrade only its independent binding result from `operator_attested` to
`live_github_verified`; runtime isolation is not assessed. Its output remains
non-authorizing:

```json
{
  "provenance_classification": "historical_evidence_verified",
  "binding_level": "live_github_verified",
  "capability_level": "lab",
  "source_repository_binding_verified": true,
  "runtime_isolation_verified": false,
  "benchmark_evaluation_allowed": false
}
```

The pilot corpus remains `lab`.

The opt-in Studio model path now uses a snapshot-bound, read-only repository
research loop instead of giving the model only one FactPack turn. The loop can
call `search_code`, `read_file_range`, and `find_callers` at most three times,
and every proposal must bind separate support and falsification evidence from
the current run. Repository content is redacted, marked untrusted, and never
persisted in the pipeline audit. This proves the bounded research mechanism,
not discovery quality: the current 20-file/20,000-character Studio intake cap,
absence of a committed multi-case real-model run, and unverified
runtime-oracle isolation keep the capability at `lab`.

The repository-history pilot also has a two-phase blind evaluation path. The
model-run command accepts only the case's `input/` directory and produces a
SHA-256-sealed prediction. The separate scoring command verifies that seal
before it opens `oracle/expected_root_cause.json` or
`oracle/evaluation.json`. Scripted or injected providers are always labelled
`mechanism_only`; only the default configured live-provider wrapper can emit
`real_model`. Every per-case result still sets `pilot_evidence_ready`,
`benchmark_claim_allowed`, `unknown_vulnerability_claim_allowed`, and
`bounty_outcome_claim_allowed` to `false`.

This verifies the in-process prompt/tool boundary and oracle-read ordering. It
does not yet prove provider-side cache/log isolation, operating-system process
isolation, multi-repository discovery quality, an unknown vulnerability, an
accepted report, or a bounty outcome. No committed real-model result exists
yet.

## Benchmark provenance prerequisites

A corpus can complete the historical-evidence prerequisites only when every
check passes:

- at least 30 verified historical-patch cases;
- at least 15 development and 15 release cases;
- at least three repository lineages in each partition;
- no repository lineage, vulnerable tree, or patch digest shared across the
  development/release boundary;
- each trusted advisory event is unique and cannot be counted in both
  partitions or duplicated toward the case threshold;
- upstream construction facts explicitly show the case was not injected,
  templated, mutated, minimized, rewritten, or created as a teaching fixture;
- an offline Git bundle reproduces both full commit IDs, proves the fixed commit
  descends from the vulnerable commit, and reproduces both source trees and the
  canonical patch;
- every source, snapshot, oracle, and bundle digest matches;
- hunter inputs are an explicit `input/` allowlist and oracle artifacts remain
  under `oracle/`;
- historical case IDs and directory names are opaque and cannot expose an
  advisory, vulnerability family, affected symbol, or expected result;
- an oracle canary is absent from every hunter-visible artifact;
- repository identity is bound to an immutable local source snapshot and a
  repository-lineage identifier;
- all safety flags deny secrets, real user data, live validation, and automatic
  report submission.

Unknown schema versions, missing evidence, stale digests, incomplete Git
history, oracle leakage, and overstated capability claims fail closed. Even a
fully complete provenance corpus remains `lab` and
`benchmark_evaluation_allowed: false` until the upstream-binding and runtime
gates exist. The audit output includes a stable `audit_digest` and verifier
version so CI can recompute and compare results without trusting a committed
result file.

## Commands

From `apps/api`:

```powershell
python -m app candidate-hunter-corpus-audit `
  --fixture-root tests/fixtures/candidate_hunter_repository_history_pilot `
  --require-level lab
```

Requiring `benchmark` must remain red until provenance, upstream binding, and
runtime isolation are all genuinely verified:

```powershell
python -m app candidate-hunter-corpus-audit `
  --fixture-root tests/fixtures/candidate_hunter_repository_history_pilot `
  --require-level benchmark
```

CI recomputes audits for all committed Candidate Hunter corpora. Audit JSON is
diagnostic evidence, not a permission token for validation, promotion, or
submission.

The ordinary pull-request gate tests upstream binding with an offline fake
transport and never depends on GitHub availability. A manual or published
release gate performs the bounded live check:

```powershell
python -m app candidate-hunter-upstream-binding-audit `
  --fixture-root tests/fixtures/candidate_hunter_repository_history_pilot `
  --output candidate-hunter-upstream-binding.json
```

The command reads `GITHUB_TOKEN` only from the environment when available. It
uses a fixed `api.github.com:443` origin, rejects redirects and non-JSON or
oversized responses, and never writes the token into the audit artifact.

Run the live model phase against hunter-visible input only:

```powershell
python -m app candidate-hunter-blind-run `
  --input-root tests/fixtures/candidate_hunter_repository_history_pilot/cases/rhp-a7c9/input `
  --case-id rhp-a7c9 `
  --suite release `
  --provider deepseek `
  --model deepseek-chat `
  --output candidate-hunter-blind-prediction.json
```

This command is opt-in, uses the selected provider's configured API key, and
may incur provider cost. It does not run in CI.

Only after the prediction file exists, score it with the evaluator-only
oracle:

```powershell
python -m app candidate-hunter-blind-score `
  --case-root tests/fixtures/candidate_hunter_repository_history_pilot/cases/rhp-a7c9 `
  --prediction candidate-hunter-blind-prediction.json `
  --output candidate-hunter-blind-evaluation.json
```

Each per-case output is an observation, not a benchmark. The committed corpus
now meets the five-case curation floor, but the blind real-model pilot is not
complete until every case is run under one locked provider/model configuration
and the sealed scores are aggregated. Benchmark claims remain subject to the
30-case repository-isolated corpus gate and human review.
