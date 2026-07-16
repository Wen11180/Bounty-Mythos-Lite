# Black-Box Dual-Intake Dataflow (HAR + Browser Demo + Studio)

Date: 2026-07-15

## Status

Working product note for the black-box path. Not an implementation authorization.

This note unifies intakes behind one research engine:

- **Browser Demo** (workflow-seeded core; product end-state)
- **HAR** (cold traffic intake; cheaper L2 bootstrap)
- **Studio Playwright** (product dual-session runtime; export `studio_recording_export_v1` → same model)

It extends:

- `docs/superpowers/specs/2026-07-14-workflow-seeded-black-box-differential-hunter-design.md`
- `docs/product/north-star.md`

Near-term priority (operator-confirmed):

- Primary battlefield: **black-box**
- No real bounty target yet → accept **L2 synthetic dual-role range** first
- A+B Falsification Card design remains secondary / deferred for white-gray path quality later

## One-Sentence Model

```text
Two intakes produce one Workflow Model.
One engine turns that model into differential plans,
bounded observations (only with lease + live sessions),
refutation, and human-review candidates.
```

HAR never becomes a second product. It is a colder way to build the same model.

## Dataflow (One Page)

```text
                    ┌─────────────────────────────┐
                    │  Authority Plane            │
                    │  policy · scope · approvals │
                    │  execution lease (remote)   │
                    └──────────────┬──────────────┘
                                   │ allow / deny
           ┌───────────────────────┴───────────────────────┐
           │                                               │
           v                                               v
 ┌─────────────────────┐                     ┌─────────────────────────┐
 │ Intake A: HAR       │                     │ Intake B: Browser Demo  │
 │ · .har file(s)      │                     │ · session_a / session_b │
 │ · optional role tag │                     │ · operator demos 1–3    │
 │ · strong redaction  │                     │   happy-path workflows  │
 └──────────┬──────────┘                     └────────────┬────────────┘
            │                                             │
            │ redacted request/response events            │ live trace events
            │ (no raw secrets persisted)                  │ (secrets in-memory only)
            └─────────────────────┬───────────────────────┘
                                  │
                    also: Studio Playwright dual_intake export
                    (templated traces; no raw secrets/IDs)
                                  │
                                  v
                    ┌─────────────────────────────┐
                    │ Workflow Normalizer         │
                    │ → Workflow Model v1         │
                    └──────────────┬──────────────┘
                                   │
                                   v
                    ┌─────────────────────────────┐
                    │ Differential Planner        │
                    │ single-variable swaps only  │
                    │ IDOR / role / object owner  │
                    └──────────────┬──────────────┘
                                   │
                    plans are hypotheses, not findings
                                   │
              ┌────────────────────┴────────────────────┐
              │                                         │
              v                                         v
 ┌────────────────────────┐              ┌────────────────────────────┐
 │ Plan-only path (HAR    │              │ Observe path (needs live   │
 │ cold, or no lease)     │              │ sessions + lease if remote)│
 │ · evidence needs       │              │ · send only planned diffs  │
 │ · safe validation plan │              │ · negative controls        │
 │ · human review card    │              │ · stability checks         │
 └───────────┬────────────┘              └─────────────┬──────────────┘
             │                                         │
             │                                         v
             │                          ┌────────────────────────────┐
             │                          │ Observation Store (redacted)│
             │                          │ success/fail · status ·    │
             │                          │ stable deltas only         │
             │                          └─────────────┬──────────────┘
             │                                        │
             └────────────────────┬───────────────────┘
                                  v
                    ┌─────────────────────────────┐
                    │ Refute / Dedupe / Rank       │
                    │ kill weak diffs             │
                    │ Top 1–5 research candidates │
                    └──────────────┬──────────────┘
                                   v
                    ┌─────────────────────────────┐
                    │ Human Review                │
                    │ → submission-blocked draft  │
                    │ never auto-submit           │
                    └─────────────────────────────┘
```

### Three Planes (must not mix)

| Plane | Holds | Must not hold |
| --- | --- | --- |
| Authority | scope, policy hash, lease id, approvals | cookies, tokens, passwords |
| Secret | ephemeral browser contexts / in-memory auth material | DB, HAR-on-disk raw, stage payloads, exports |
| Research | workflow model, plans, redacted observations, candidates | raw `Authorization` / `Cookie` / session resumes |

## Intake Comparison (Engine View)

| Step | HAR intake | Browser Demo intake |
| --- | --- | --- |
| Build Workflow Model | Yes (inferred order, weaker ownership) | Yes (stronger ownership + live roles) |
| Produce differential plans | Yes | Yes |
| Execute observations | No by default (plan-only unless operator later attaches live sessions + lease) | Yes when lease/session rules allow |
| Secret risk | High if HAR stored raw → redact at import, drop auth headers | High if profiles persisted → never serialize session material |
| Best use now | L2 bootstrap on local dual-role range | Product-shaped path after L2 proves ranking quality |

## Shared Engine Contracts

### 1) Workflow Model v1 (minimum fields)

Produced by either intake after redaction.

```json
{
  "schema_version": "workflow_model_v1",
  "workflow_id": "wf_...",
  "source": "har|browser_demo|merged",
  "role_bindings": [
    { "role_alias": "role_a", "session_ref": "session_a|null", "label": "user_a" },
    { "role_alias": "role_b", "session_ref": "session_b|null", "label": "user_b" }
  ],
  "steps": [
    {
      "step_id": "s1",
      "method": "GET",
      "path_template": "/api/orders/{order_id}",
      "path_params": ["order_id"],
      "query_keys": [],
      "body_keys": [],
      "actor_role": "role_a",
      "success_status_class": "2xx",
      "object_refs": ["obj:order:order_id"],
      "event_refs": ["evt:..."]
    }
  ],
  "objects": [
    {
      "object_ref": "obj:order:order_id",
      "object_type": "order",
      "id_param": "order_id",
      "owner_role": "role_a",
      "sample_id_alias": "owned_by_a"
    }
  ],
  "safety": {
    "raw_secrets_persisted": false,
    "execution_allowed": false,
    "report_submission_allowed": false
  }
}
```

Rules:

- `path_template` uses placeholders; never store full URL with live tokens.
- Object IDs in research plane are **aliases** (`owned_by_a`), not necessarily raw production IDs in exports.
- HAR without two roles may set `session_ref` null and mark ownership confidence low.
- Missing ownership → planner may emit plans, but rank/retain must stay conservative (`needs_evidence` / low rank).

### 2) Differential Plan v1 (minimum fields)

```json
{
  "schema_version": "differential_plan_v1",
  "plan_id": "dp_...",
  "workflow_id": "wf_...",
  "family": "idor_bola|privilege_boundary|authz_state",
  "variable": {
    "kind": "object_id|role|both",
    "name": "order_id",
    "from_object_ref": "obj:order:order_id"
  },
  "baseline": {
    "actor_role": "role_a",
    "step_id": "s1",
    "expected": "allow_on_owner"
  },
  "probe": {
    "actor_role": "role_b",
    "step_id": "s1",
    "swap": { "order_id": "alias:owned_by_a" },
    "expected_secure": "deny_or_empty"
  },
  "negative_controls": [
    { "name": "same_role_owner_still_works", "must": "allow" },
    { "name": "random_id_not_confused_with_idor", "must": "deny_or_empty" }
  ],
  "execution": {
    "mode": "plan_only|lease_bound_observe",
    "requires_live_sessions": true,
    "requires_lease_if_remote": true,
    "state_change": "none|reversible_own_object_only"
  },
  "safety_blockers": [
    "no_raw_secret_export",
    "no_real_user_data",
    "no_high_frequency_scan",
    "no_auto_submit"
  ]
}
```

Rules:

- Exactly **one** intentional variable per plan (single-variable discipline).
- No plan may require destructive actions, password spray, or third-party user objects.
- `plan_only` is the default for HAR-cold runs.

### 3) Observation v1 (minimum fields; only if executed)

```json
{
  "schema_version": "diff_observation_v1",
  "observation_id": "obs_...",
  "plan_id": "dp_...",
  "stable": true,
  "repro_count": 2,
  "baseline_result": { "status": 200, "outcome": "allow", "body_fingerprint": "fp_..." },
  "probe_result": { "status": 200, "outcome": "allow", "body_fingerprint": "fp_..." },
  "control_results": [
    { "name": "same_role_owner_still_works", "passed": true }
  ],
  "redacted_evidence_refs": ["ev:..."],
  "secrets_present": false
}
```

Rules:

- Persist fingerprints / redacted excerpts only; never raw auth headers or full account dumps.
- `stable=false` or failed negative control → cannot enter Top retained set as a strong candidate.

### 4) Candidate Card v1 (human review)

```json
{
  "schema_version": "bb_candidate_v1",
  "candidate_id": "bbc_...",
  "family": "idor_bola",
  "title": "role_b can read role_a order by id swap",
  "workflow_id": "wf_...",
  "plan_id": "dp_...",
  "affected_endpoint": "GET /api/orders/{order_id}",
  "broken_invariant": "Only the owner role may read an order object",
  "observation_ids": ["obs_..."],
  "why_alive": ["probe allow + controls passed + stable"],
  "why_dead_or_weak": [],
  "evidence_gaps": [],
  "safe_validation_plan": ["human recheck on test objects only"],
  "decision": "retained|refuted|suppressed|needs_evidence",
  "execution_allowed": false,
  "validation_allowed": false,
  "report_submission_allowed": false
}
```

Note: later, A+B falsification taxonomy can map onto `why_alive` / `why_dead_or_weak` without changing this black-box card spine.

## V1 Slice Recommendation (no real target)

### Accept L2 only

Build or select a **local dual-role intentional IDOR app**:

- `user_a` / `user_b`
- `GET /orders/{id}` missing owner check (true positive seed)
- at least one distractor (public list, expired session, owner-only that works)

### V1 intake choice

| Order | Intake | Why |
| --- | --- | --- |
| V1a | HAR from the local range (A and B flows) | Fastest proof of normalizer + planner + rank/refute |
| V1b | Browser Demo on the same range | Proves secret plane + session broker + lease-shaped observe |

Do not require remote bounty targets for V1a/V1b.

### V1 success criteria

1. True seeded IDOR reaches Top retained with endpoint + invariant + plan/observation link.
2. Distractors die (`refuted` / `suppressed`) with explicit why-dead reasons.
3. No raw cookie/token in DB, stage payloads, exports, or candidate cards.
4. Without lease + live sessions, engine stays plan-only (no request spam).
5. Report submission remains blocked.

## Explicit Non-Goals for This Note

- Implementing browser automation in this document
- Public-target scanning or high-frequency crawling
- Treating plan-only HAR output as confirmed vulns
- Replacing A+B local-code hunter (it stays a parallel path)
- Dashboard completeness

## Decision Defaults (until operator overrides)

1. **Near-term mainline:** black-box engine above; A+B only for blocking fixes.
2. **First build:** Workflow Model + Differential Planner + plan-only candidate projection from HAR.
3. **Second build:** attach Browser Demo sessions and lease-bound observe on local range.
4. **Falsification-first A+B card:** deferred; reuse kill ideas later on black-box observations.
5. **Real bounty target:** not required until L2 criteria pass; then operator supplies authorized program package.

## Open Points Still Worth a One-Line Call

1. HAR role labeling: two files (`a.har` / `b.har`) vs one file + manual role tags?
2. Object aliasing: always alias IDs in exports, or allow raw test IDs on local-only workspaces?
3. V1a observe: stay plan-only, or allow local-range auto-observe without formal remote lease?

Recommended defaults: **two HARs or tagged roles**, **alias in any export**, **local range may auto-observe behind an explicit local_lab flag; remote always needs lease**.
