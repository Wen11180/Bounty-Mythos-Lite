# Candidate Hunter capability levels

The capability label is derived from evidence. A corpus manifest may request a
level, but it cannot grant that level to itself.

## Levels

| Level | Meaning | Evidence source |
| --- | --- | --- |
| `lab` | Synthetic, teaching, minimized, or otherwise laboratory cases | Local fixture tests |
| `benchmark` | Repository-isolated historical vulnerabilities with hidden oracle material and reproducible upstream history | Offline provenance gate |
| `field_proven` | Externally reviewed outcomes from authorized engagements | Separate human-reviewed outcome record |

The current corpus gate proves provenance prerequisites only. It cannot grant
`benchmark` until a separate gate binds commits to the declared upstream
repository and verifies runtime isolation across prompt, trace, output, cache,
and logs. It always rejects `field_proven` because a fixture cannot prove
accepted reports or bounty outcomes.

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

The repository-history pilot contains one offline evidence-verified historical
case:
[`fastify/fast-uri` GHSA-q3j6-qgpj-74h6](https://github.com/fastify/fast-uri/security/advisories/GHSA-q3j6-qgpj-74h6).
The local Git evidence is internally reproducible, but repository binding is
currently operator-attested and runtime isolation is not assessed. Its output
therefore remains non-authorizing:

```json
{
  "provenance_classification": "historical_evidence_verified",
  "source_repository_binding": "operator_attested",
  "runtime_isolation_verified": false,
  "benchmark_evaluation_allowed": false
}
```

The pilot corpus remains `lab`.

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
