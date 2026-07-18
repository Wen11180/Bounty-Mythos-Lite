import assert from "node:assert/strict";
import test from "node:test";

import {
  isSafeProgramRuleRegistration,
  programRuleErrorMessage,
  toProgramRuleDiffView,
  toProgramRuleSnapshotView,
  toProgramRuleSourceView,
  toProgramScopeRuleView,
} from "./program-rule-data.ts";

const SHA = "a".repeat(64);
const permissions = {
  execution_allowed: false,
  lease_grant_allowed: false,
  report_submission_allowed: false,
  review_bypass_allowed: false,
  scope_change_allowed: false,
} as const;

test("program-rule source mapper separates fetch and effective states", () => {
  const view = toProgramRuleSourceView({
    approved_snapshot_id: null,
    canonical_url: "https://rules.example.test/program",
    effective_scope_status: "active",
    fetch_status: "fetching",
    last_success_at: null,
    next_check_at: "2026-07-19T12:00:00Z",
    pending_snapshot_id: "snapshot_pending",
    program_alias: "synthetic_program",
    program_id: "program_synthetic",
    registered_url: "https://rules.example.test/program",
    source_id: "source_synthetic",
    warning: null,
  });

  assert.equal(view.fetchStatus, "fetching");
  assert.equal(view.effectiveStatus, "active");
  assert.equal(view.reviewPending, true);
  assert.equal(view.contractStatus, "valid");
});

test("unknown statuses and authority drift map to review-required fixed-false views", () => {
  const source = toProgramRuleSourceView({
    canonical_url: "https://rules.example.test/program",
    effective_scope_status: "execute_everything",
    execution_allowed: true,
    fetch_status: "verified",
    program_alias: "synthetic_program",
    registered_url: "https://rules.example.test/program",
    source_id: "source_synthetic",
  });
  const snapshot = toProgramRuleSnapshotView({
    ...snapshotFixture(),
    execution_allowed: true,
    report_submission_allowed: "yes",
    review_status: "verified",
  });

  assert.equal(source.fetchStatus, "failed");
  assert.equal(source.effectiveStatus, "needs_review");
  assert.equal(source.contractStatus, "invalid");
  assert.deepEqual(source.permissions, fixedFalseView());
  assert.equal(snapshot.reviewStatus, "pending");
  assert.equal(snapshot.contractStatus, "invalid");
  assert.deepEqual(snapshot.permissions, fixedFalseView());
});

test("snapshot mapper enumerates review-safe fields and caps evidence excerpts", () => {
  const view = toProgramRuleSnapshotView({
    ...snapshotFixture(),
    evidence: [{
      document_sha256: SHA,
      evidence_id: SHA,
      excerpt: `Allowed scope ${"x".repeat(700)}`,
      locator: "line:1",
      raw_html: "<script>secret()</script>",
      response_headers: { authorization: "Bearer secret" },
    }],
    raw_body: "must-not-render",
  });

  assert.equal(view.evidence[0]?.excerpt.length, 500);
  assert.equal(view.language, "en");
  assert.equal(view.aiStatus, "not_requested");
  assert.equal(view.linkedDocuments[0]?.normalizedSha256, SHA);
  assert.equal(view.linkedArtifacts[0]?.normalizedSha256, SHA);
  const serialized = JSON.stringify(view);
  assert.doesNotMatch(serialized, /script|authorization|Bearer|raw_body|response_headers/iu);
});

test("diff and scope mappers preserve review facts but never authority", () => {
  const candidate = candidateRule("api.example.test");
  const diff = toProgramRuleDiffView({
    ...permissions,
    added_linked_artifacts: [linkedArtifact()],
    added_prohibitions: ["automated_scanning"],
    added_rules: [candidate],
    approved_snapshot_id: null,
    modified_rules: [{ after: candidateRule("api.example.test/v2"), asset: candidate.asset, before: candidate }],
    pending_snapshot_id: "snapshot_pending",
    removed_linked_artifacts: [],
    removed_prohibitions: ["legacy_rule"],
    removed_rules: [],
    review_digest: SHA,
    source_id: "source_synthetic",
  });
  const scope = toProgramScopeRuleView({
    ...permissions,
    allowed_validation: ["manual_read_only"],
    approval_digest: SHA,
    approved_snapshot_id: "snapshot_approved",
    asset_kind: "exact_host",
    automation: "limited",
    canonical_asset: "api.example.test",
    effective_at: "2026-07-18T12:00:00Z",
    effective_scope_status: "active",
    prohibited: ["automated_scanning"],
    program_id: "program_synthetic",
    rate_limit: { evidence_ids: [SHA], period: 1, requests: 5, unit: "minute" },
    rule_id: "rule_synthetic",
    scope_status: "in_scope",
    source_evidence_refs: [SHA],
    source_id: "source_synthetic",
    warning: null,
  });

  assert.equal(diff.addedRules[0]?.asset, "api.example.test");
  assert.equal(diff.modifiedRules[0]?.after.asset, "api.example.test/v2");
  assert.deepEqual(diff.permissions, fixedFalseView());
  assert.equal(scope.rateLimit, "5 per minute");
  assert.deepEqual(scope.permissions, fixedFalseView());
});

test("registration validator accepts only safe aliases and canonical public HTTPS URLs", () => {
  assert.equal(isSafeProgramRuleRegistration({
    programAlias: "synthetic_program",
    publicRuleUrl: "https://rules.example.test/program",
  }), true);

  for (const publicRuleUrl of [
    "http://rules.example.test/program",
    "https://user:password@rules.example.test/program",
    "https://rules.example.test/program#scope",
    "https://rules.example.test/program?token=secret",
    "https://localhost/program",
  ]) {
    assert.equal(isSafeProgramRuleRegistration({
      programAlias: "synthetic_program",
      publicRuleUrl,
    }), false);
  }
  assert.equal(isSafeProgramRuleRegistration({
    programAlias: "unsafe alias",
    publicRuleUrl: "https://rules.example.test/program",
  }), false);
});

test("operator errors are reduced to fixed safe review messages", () => {
  assert.equal(programRuleErrorMessage({ status: 409 }), "stale_or_conflicting_review");
  assert.equal(programRuleErrorMessage({ status: 429 }), "refresh_cooldown");
  assert.equal(programRuleErrorMessage({ status: 0 }), "api_unavailable");
  assert.equal(
    programRuleErrorMessage({ detail: "database password leaked", status: 500 }),
    "request_failed",
  );
});

function snapshotFixture() {
  return {
    ...permissions,
    ai_status: "not_requested",
    artifact_warning: null,
    content_types: ["text/html"],
    detected_language: "en",
    evidence: [],
    extraction: { review_issues: [], review_state: "ready", rules: [candidateRule("api.example.test")] },
    fetched_at: "2026-07-18T12:00:00Z",
    fetch_mode: "static",
    linked_documents: [{
      content_type: "text/plain",
      depth: 1,
      kind: "text",
      normalized_sha256: SHA,
      raw_sha256: SHA,
      url: "https://rules.example.test/linked",
    }],
    normalized_sha256: SHA,
    openapi_candidates: [linkedArtifact()],
    raw_aggregate_sha256: SHA,
    review_digest: SHA,
    review_status: "pending",
    reviewed_at: null,
    reviewer_alias: null,
    snapshot_id: "snapshot_pending",
    source_id: "source_synthetic",
  };
}

function candidateRule(asset: string) {
  return {
    allowed_validation: ["manual_read_only"],
    asset,
    asset_kind: "exact_host",
    automation: "limited",
    automation_evidence_ids: [SHA],
    human_approval_required: true,
    prohibited: ["automated_scanning"],
    prohibited_evidence_ids: { automated_scanning: [SHA] },
    rate_limit: { evidence_ids: [SHA], period: 1, requests: 5, unit: "minute" },
    review_issues: [],
    review_state: "ready",
    scope_evidence_ids: [SHA],
    scope_status: "in_scope",
    specificity: 4,
  };
}

function linkedArtifact() {
  return {
    evidence_ids: [SHA],
    kind: "openapi",
    normalized_sha256: SHA,
    openapi_like: { path_count: 1 },
    promotion_allowed: false,
    url: "https://rules.example.test/openapi.json",
    url_sha256: SHA,
  };
}

function fixedFalseView() {
  return {
    executionAllowed: false,
    leaseGrantAllowed: false,
    reportSubmissionAllowed: false,
    reviewBypassAllowed: false,
    scopeChangeAllowed: false,
  };
}
