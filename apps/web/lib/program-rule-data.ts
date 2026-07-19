export type ProgramRuleFixedFalsePermissions = {
  execution_allowed: false;
  lease_grant_allowed: false;
  report_submission_allowed: false;
  review_bypass_allowed: false;
  scope_change_allowed: false;
};

export type ProgramRuleFetchStatus =
  | "browser_render_required"
  | "failed"
  | "fetching"
  | "ok"
  | "scheduled";
export type ProgramRuleEffectiveStatus = "active" | "frozen" | "needs_review";
export type ProgramRuleReviewStatus = "approved" | "pending" | "rejected";
export type ProgramRuleScopeStatus = "in_scope" | "needs_review" | "out_of_scope";
export type ProgramRuleAutomation = "limited" | "needs_review" | "none";

export type ProgramRuleSource = {
  approved_snapshot_id: string | null;
  canonical_url: string;
  effective_scope_status: ProgramRuleEffectiveStatus;
  fetch_status: ProgramRuleFetchStatus;
  last_success_at: string | null;
  next_check_at: string;
  pending_snapshot_id: string | null;
  program_alias: string;
  program_id: string | null;
  registered_url: string;
  source_id: string;
  warning: string | null;
};

export type ProgramRuleRateLimit = {
  evidence_ids: string[];
  period: number;
  requests: number;
  unit: "day" | "hour" | "minute" | "second";
};

export type ProgramRuleCandidate = {
  allowed_validation: string[];
  asset: string;
  asset_kind: "api_base_path" | "exact_host" | "url_prefix" | "wildcard_host";
  automation: ProgramRuleAutomation;
  automation_evidence_ids: string[];
  human_approval_required: true;
  prohibited: string[];
  prohibited_evidence_ids: Record<string, string[]>;
  rate_limit: ProgramRuleRateLimit | null;
  review_issues: string[];
  review_state: "needs_review" | "ready";
  scope_evidence_ids: string[];
  scope_status: ProgramRuleScopeStatus;
  specificity: 1 | 2 | 3 | 4;
};

export type ProgramRuleEvidence = {
  document_sha256: string;
  evidence_id: string;
  excerpt: string;
  locator: string;
};

export type ProgramRuleLinkedArtifact = {
  evidence_ids: string[];
  kind: "openapi";
  normalized_sha256: string;
  openapi_like: Record<string, unknown>;
  promotion_allowed: false;
  url: string;
  url_sha256: string;
};

export type ProgramRuleLinkedDocument = {
  content_type: string;
  depth: 1;
  kind: "html" | "json" | "text" | "yaml";
  normalized_sha256: string;
  raw_sha256: string | null;
  url: string;
};

export type ProgramRuleSnapshot = ProgramRuleFixedFalsePermissions & {
  ai_status: "not_requested" | "ok" | "rejected" | "unavailable";
  artifact_warning: "openapi_promotion_pending" | null;
  content_types: string[];
  detected_language: "en" | "unsupported";
  evidence: ProgramRuleEvidence[];
  extraction: {
    review_issues?: string[];
    review_state?: "needs_review" | "ready";
    rules?: ProgramRuleCandidate[];
  };
  fetched_at: string;
  fetch_mode: "browser" | "static";
  linked_documents: ProgramRuleLinkedDocument[];
  normalized_sha256: string;
  openapi_candidates: ProgramRuleLinkedArtifact[];
  raw_aggregate_sha256: string;
  review_digest: string;
  review_status: ProgramRuleReviewStatus;
  reviewed_at: string | null;
  reviewer_alias: string | null;
  snapshot_id: string;
  source_id: string;
};

export type ProgramRuleSnapshotDiff = ProgramRuleFixedFalsePermissions & {
  added_linked_artifacts: ProgramRuleLinkedArtifact[];
  added_prohibitions: string[];
  added_rules: ProgramRuleCandidate[];
  approved_snapshot_id: string | null;
  modified_rules: Array<{
    after: ProgramRuleCandidate;
    asset: string;
    before: ProgramRuleCandidate;
  }>;
  pending_snapshot_id: string;
  removed_linked_artifacts: ProgramRuleLinkedArtifact[];
  removed_prohibitions: string[];
  removed_rules: ProgramRuleCandidate[];
  review_digest: string;
  source_id: string;
};

export type ProgramScopeRule = ProgramRuleFixedFalsePermissions & {
  allowed_validation: string[];
  approval_digest: string;
  approved_snapshot_id: string;
  asset_kind: "api_base_path" | "exact_host" | "url_prefix" | "wildcard_host";
  automation: ProgramRuleAutomation;
  canonical_asset: string;
  effective_at: string;
  effective_scope_status: ProgramRuleEffectiveStatus;
  prohibited: string[];
  program_id: string;
  rate_limit: ProgramRuleRateLimit | null;
  rule_id: string;
  scope_status: ProgramRuleScopeStatus;
  source_evidence_refs: string[];
  source_id: string;
  warning: string | null;
};

export type ProgramRuleRegistrationInput = {
  program_alias: string;
  public_rule_url: string;
};

export type ProgramRuleReviewInput = {
  expected_review_digest: string;
  operator_confirmed: true;
  reviewer_alias: string;
};

export type SafeRefreshStatus = {
  next_due_at: string | null;
  processed: boolean;
  status: "completed" | "failed" | "idle";
};

type ContractStatus = "invalid" | "valid";
type AuthorityStatus = "fixed_false" | "invalid";

export type FixedFalsePermissionView = {
  executionAllowed: false;
  leaseGrantAllowed: false;
  reportSubmissionAllowed: false;
  reviewBypassAllowed: false;
  scopeChangeAllowed: false;
};

export type ProgramRuleSourceView = {
  approvedSnapshotId: string | null;
  authorityStatus: AuthorityStatus;
  canonicalUrl: string;
  contractStatus: ContractStatus;
  effectiveStatus: ProgramRuleEffectiveStatus;
  fetchStatus: ProgramRuleFetchStatus;
  lastSuccessAt: string | null;
  nextCheckAt: string | null;
  pendingSnapshotId: string | null;
  permissions: FixedFalsePermissionView;
  programAlias: string;
  programId: string | null;
  registeredUrl: string;
  reviewPending: boolean;
  sourceId: string;
  warning: string | null;
};

export type ProgramRuleCandidateView = {
  allowedValidation: string[];
  asset: string;
  assetKind: string;
  automation: ProgramRuleAutomation;
  prohibited: string[];
  rateLimit: string | null;
  reviewIssues: string[];
  reviewState: "needs_review" | "ready";
  scopeStatus: ProgramRuleScopeStatus;
};

export type ProgramRuleSnapshotView = {
  aiStatus: "not_requested" | "ok" | "rejected" | "unavailable";
  artifactWarning: "openapi_promotion_pending" | null;
  authorityStatus: AuthorityStatus;
  contentTypes: string[];
  contractStatus: ContractStatus;
  evidence: ProgramRuleEvidenceView[];
  fetchedAt: string | null;
  fetchMode: "browser" | "static" | "unknown";
  language: "en" | "unsupported";
  linkedArtifacts: ProgramRuleLinkedArtifactView[];
  linkedDocuments: ProgramRuleLinkedDocumentView[];
  normalizedSha256: string;
  permissions: FixedFalsePermissionView;
  reviewDigest: string;
  reviewIssues: string[];
  reviewStatus: ProgramRuleReviewStatus;
  reviewedAt: string | null;
  reviewerAlias: string | null;
  rules: ProgramRuleCandidateView[];
  snapshotId: string;
  sourceId: string;
};

export type ProgramRuleEvidenceView = {
  documentSha256: string;
  evidenceId: string;
  excerpt: string;
  locator: string;
};

export type ProgramRuleLinkedDocumentView = {
  contentType: string;
  kind: string;
  normalizedSha256: string;
};

export type ProgramRuleLinkedArtifactView = {
  evidenceIds: string[];
  normalizedSha256: string;
  promotionAllowed: false;
  urlSha256: string;
};

export type ProgramRuleDiffView = {
  addedLinkedArtifacts: ProgramRuleLinkedArtifactView[];
  addedProhibitions: string[];
  addedRules: ProgramRuleCandidateView[];
  approvedSnapshotId: string | null;
  authorityStatus: AuthorityStatus;
  contractStatus: ContractStatus;
  modifiedRules: Array<{
    after: ProgramRuleCandidateView;
    asset: string;
    before: ProgramRuleCandidateView;
  }>;
  pendingSnapshotId: string;
  permissions: FixedFalsePermissionView;
  removedLinkedArtifacts: ProgramRuleLinkedArtifactView[];
  removedProhibitions: string[];
  removedRules: ProgramRuleCandidateView[];
  reviewDigest: string;
  sourceId: string;
};

export type ProgramScopeRuleView = ProgramRuleCandidateView & {
  authorityStatus: AuthorityStatus;
  contractStatus: ContractStatus;
  effectiveStatus: ProgramRuleEffectiveStatus;
  permissions: FixedFalsePermissionView;
  rateLimit: string | null;
  ruleId: string;
  warning: string | null;
};

const falsePermissions: FixedFalsePermissionView = Object.freeze({
  executionAllowed: false,
  leaseGrantAllowed: false,
  reportSubmissionAllowed: false,
  reviewBypassAllowed: false,
  scopeChangeAllowed: false,
});
const permissionKeys = [
  "execution_allowed",
  "lease_grant_allowed",
  "report_submission_allowed",
  "review_bypass_allowed",
  "scope_change_allowed",
] as const;
const fetchStatuses = new Set<ProgramRuleFetchStatus>([
  "browser_render_required", "failed", "fetching", "ok", "scheduled",
]);
const effectiveStatuses = new Set<ProgramRuleEffectiveStatus>([
  "active", "frozen", "needs_review",
]);
const reviewStatuses = new Set<ProgramRuleReviewStatus>(["approved", "pending", "rejected"]);
const scopeStatuses = new Set<ProgramRuleScopeStatus>(["in_scope", "needs_review", "out_of_scope"]);
const automationStatuses = new Set<ProgramRuleAutomation>(["limited", "needs_review", "none"]);
const aiStatuses = new Set<ProgramRuleSnapshotView["aiStatus"]>([
  "not_requested", "ok", "rejected", "unavailable",
]);
const secretQueryKeys = new Set([
  "accesstoken", "apikey", "auth", "authorization", "cookie", "credential", "jwt",
  "password", "secret", "session", "sessionid", "token",
]);

export function toProgramRuleSourceView(value: unknown): ProgramRuleSourceView {
  const source = record(value);
  const fetchStatus = enumValue(source.fetch_status, fetchStatuses, "failed");
  const effectiveStatus = enumValue(source.effective_scope_status, effectiveStatuses, "needs_review");
  const sourceId = boundedString(source.source_id, 128, "unknown_source");
  const programAlias = boundedString(source.program_alias, 64, "needs_review");
  const registeredUrl = boundedString(source.registered_url, 2_048, "unavailable");
  const canonicalUrl = boundedString(source.canonical_url, 2_048, "unavailable");
  const authorityStatus = hasUnexpectedAuthority(source) ? "invalid" : "fixed_false";
  const contractValid = (
    sourceId !== "unknown_source"
    && programAlias !== "needs_review"
    && registeredUrl !== "unavailable"
    && canonicalUrl !== "unavailable"
    && fetchStatuses.has(source.fetch_status as ProgramRuleFetchStatus)
    && effectiveStatuses.has(source.effective_scope_status as ProgramRuleEffectiveStatus)
    && authorityStatus === "fixed_false"
  );
  const pendingSnapshotId = nullableString(source.pending_snapshot_id, 128);
  return {
    approvedSnapshotId: nullableString(source.approved_snapshot_id, 128),
    authorityStatus,
    canonicalUrl,
    contractStatus: contractValid ? "valid" : "invalid",
    effectiveStatus,
    fetchStatus,
    lastSuccessAt: safeDate(source.last_success_at),
    nextCheckAt: safeDate(source.next_check_at),
    pendingSnapshotId,
    permissions: fixedFalsePermissionView(),
    programAlias,
    programId: nullableString(source.program_id, 128),
    registeredUrl,
    reviewPending: pendingSnapshotId !== null,
    sourceId,
    warning: nullableString(source.warning, 500),
  };
}

export function toProgramRuleSnapshotView(value: unknown): ProgramRuleSnapshotView {
  const snapshot = record(value);
  const extraction = record(snapshot.extraction);
  const reviewStatus = enumValue(snapshot.review_status, reviewStatuses, "pending");
  const authorityStatus = fixedFalseAuthority(snapshot) ? "fixed_false" : "invalid";
  const normalizedSha256 = sha256(snapshot.normalized_sha256);
  const reviewDigest = sha256(snapshot.review_digest);
  const snapshotId = boundedString(snapshot.snapshot_id, 128, "unknown_snapshot");
  const sourceId = boundedString(snapshot.source_id, 128, "unknown_source");
  const contractValid = (
    authorityStatus === "fixed_false"
    && reviewStatuses.has(snapshot.review_status as ProgramRuleReviewStatus)
    && aiStatuses.has(snapshot.ai_status as ProgramRuleSnapshotView["aiStatus"])
    && ["en", "unsupported"].includes(String(snapshot.detected_language))
    && ["browser", "static"].includes(String(snapshot.fetch_mode))
    && normalizedSha256 !== "unavailable"
    && reviewDigest !== "unavailable"
    && snapshotId !== "unknown_snapshot"
    && sourceId !== "unknown_source"
  );
  return {
    aiStatus: enumValue(snapshot.ai_status, aiStatuses, "rejected"),
    artifactWarning: snapshot.artifact_warning === "openapi_promotion_pending"
      ? "openapi_promotion_pending"
      : null,
    authorityStatus,
    contentTypes: stringArray(snapshot.content_types, 100, 100),
    contractStatus: contractValid ? "valid" : "invalid",
    evidence: array(snapshot.evidence, 500).map(toEvidenceView),
    fetchedAt: safeDate(snapshot.fetched_at),
    fetchMode: snapshot.fetch_mode === "browser" || snapshot.fetch_mode === "static"
      ? snapshot.fetch_mode
      : "unknown",
    language: snapshot.detected_language === "en" ? "en" : "unsupported",
    linkedArtifacts: array(snapshot.openapi_candidates, 100).map(toLinkedArtifactView),
    linkedDocuments: array(snapshot.linked_documents, 8).map(toLinkedDocumentView),
    normalizedSha256,
    permissions: fixedFalsePermissionView(),
    reviewDigest,
    reviewIssues: stringArray(extraction.review_issues, 100, 500),
    reviewStatus,
    reviewedAt: safeDate(snapshot.reviewed_at),
    reviewerAlias: nullableString(snapshot.reviewer_alias, 100),
    rules: array(extraction.rules, 500).map(toCandidateView),
    snapshotId,
    sourceId,
  };
}

export function toProgramRuleDiffView(value: unknown): ProgramRuleDiffView {
  const diff = record(value);
  const authorityStatus = fixedFalseAuthority(diff) ? "fixed_false" : "invalid";
  const pendingSnapshotId = boundedString(diff.pending_snapshot_id, 128, "unknown_snapshot");
  const reviewDigest = sha256(diff.review_digest);
  const sourceId = boundedString(diff.source_id, 128, "unknown_source");
  const contractValid = (
    authorityStatus === "fixed_false"
    && pendingSnapshotId !== "unknown_snapshot"
    && reviewDigest !== "unavailable"
    && sourceId !== "unknown_source"
  );
  return {
    addedLinkedArtifacts: array(diff.added_linked_artifacts, 100).map(toLinkedArtifactView),
    addedProhibitions: stringArray(diff.added_prohibitions, 500, 500),
    addedRules: array(diff.added_rules, 500).map(toCandidateView),
    approvedSnapshotId: nullableString(diff.approved_snapshot_id, 128),
    authorityStatus,
    contractStatus: contractValid ? "valid" : "invalid",
    modifiedRules: array(diff.modified_rules, 500).map((item) => {
      const modification = record(item);
      return {
        after: toCandidateView(modification.after),
        asset: boundedString(modification.asset, 2_048, "needs_review"),
        before: toCandidateView(modification.before),
      };
    }),
    pendingSnapshotId,
    permissions: fixedFalsePermissionView(),
    removedLinkedArtifacts: array(diff.removed_linked_artifacts, 100).map(toLinkedArtifactView),
    removedProhibitions: stringArray(diff.removed_prohibitions, 500, 500),
    removedRules: array(diff.removed_rules, 500).map(toCandidateView),
    reviewDigest,
    sourceId,
  };
}

export function toProgramScopeRuleView(value: unknown): ProgramScopeRuleView {
  const rule = record(value);
  const authorityStatus = fixedFalseAuthority(rule) ? "fixed_false" : "invalid";
  const effectiveStatus = enumValue(rule.effective_scope_status, effectiveStatuses, "needs_review");
  const ruleId = boundedString(rule.rule_id, 128, "unknown_rule");
  const candidate = toCandidateView({
    allowed_validation: rule.allowed_validation,
    asset: rule.canonical_asset,
    asset_kind: rule.asset_kind,
    automation: rule.automation,
    prohibited: rule.prohibited,
    rate_limit: rule.rate_limit,
    review_issues: [],
    review_state: "ready",
    scope_status: rule.scope_status,
  });
  const contractValid = (
    authorityStatus === "fixed_false"
    && effectiveStatuses.has(rule.effective_scope_status as ProgramRuleEffectiveStatus)
    && scopeStatuses.has(rule.scope_status as ProgramRuleScopeStatus)
    && automationStatuses.has(rule.automation as ProgramRuleAutomation)
    && ["api_base_path", "exact_host", "url_prefix", "wildcard_host"].includes(
      String(rule.asset_kind),
    )
    && boundedString(rule.canonical_asset, 2_048, "needs_review") !== "needs_review"
    && boundedString(rule.source_id, 128, "unknown_source") !== "unknown_source"
    && boundedString(rule.program_id, 128, "unknown_program") !== "unknown_program"
    && boundedString(rule.approved_snapshot_id, 128, "unknown_snapshot") !== "unknown_snapshot"
    && sha256(rule.approval_digest) !== "unavailable"
    && ruleId !== "unknown_rule"
  );
  return {
    ...candidate,
    authorityStatus,
    contractStatus: contractValid ? "valid" : "invalid",
    effectiveStatus,
    permissions: fixedFalsePermissionView(),
    rateLimit: rateLimitLabel(rule.rate_limit),
    ruleId,
    warning: nullableString(rule.warning, 500),
  };
}

export function isProgramRuleReviewBindingValid(
  source: ProgramRuleSourceView | null,
  snapshot: ProgramRuleSnapshotView | null,
  diff: ProgramRuleDiffView | null,
): boolean {
  return Boolean(
    source
    && snapshot
    && diff
    && source.contractStatus === "valid"
    && source.authorityStatus === "fixed_false"
    && snapshot.contractStatus === "valid"
    && snapshot.authorityStatus === "fixed_false"
    && diff.contractStatus === "valid"
    && diff.authorityStatus === "fixed_false"
    && source.reviewPending
    && source.pendingSnapshotId === snapshot.snapshotId
    && snapshot.sourceId === source.sourceId
    && diff.sourceId === source.sourceId
    && diff.pendingSnapshotId === snapshot.snapshotId
    && diff.reviewDigest === snapshot.reviewDigest
  );
}

export function isSafeProgramRuleRegistration(value: {
  programAlias: string;
  publicRuleUrl: string;
}): boolean {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(value.programAlias)) return false;
  const url = value.publicRuleUrl;
  if (
    typeof url !== "string"
    || url.length < 1
    || url.length > 2_048
    || url.includes("\\")
    || /[\s\p{C}]/u.test(url)
  ) return false;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.hash !== ""
    || parsed.href !== url
    || !parsed.hostname.includes(".")
    || parsed.port === "0"
  ) return false;
  for (const [key, queryValue] of parsed.searchParams) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
    if (
      secretQueryKeys.has(normalizedKey)
      || /^(?:basic |bearer |ghp_|github_pat_|sk-|xox[bp]-)/iu.test(queryValue)
      || /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{6,}$/u.test(queryValue)
    ) return false;
  }
  return true;
}

export function programRuleErrorMessage(error: unknown):
  | "api_unavailable"
  | "refresh_cooldown"
  | "request_failed"
  | "stale_or_conflicting_review" {
  const status = record(error).status;
  if (status === 409) return "stale_or_conflicting_review";
  if (status === 429) return "refresh_cooldown";
  if (status === 0) return "api_unavailable";
  return "request_failed";
}

function toCandidateView(value: unknown): ProgramRuleCandidateView {
  const candidate = record(value);
  return {
    allowedValidation: stringArray(candidate.allowed_validation, 100, 200),
    asset: boundedString(candidate.asset, 2_048, "needs_review"),
    assetKind: boundedString(candidate.asset_kind, 50, "needs_review"),
    automation: enumValue(candidate.automation, automationStatuses, "needs_review"),
    prohibited: stringArray(candidate.prohibited, 500, 500),
    rateLimit: rateLimitLabel(candidate.rate_limit),
    reviewIssues: stringArray(candidate.review_issues, 100, 500),
    reviewState: candidate.review_state === "ready" ? "ready" : "needs_review",
    scopeStatus: enumValue(candidate.scope_status, scopeStatuses, "needs_review"),
  };
}

function toEvidenceView(value: unknown): ProgramRuleEvidenceView {
  const evidence = record(value);
  return {
    documentSha256: sha256(evidence.document_sha256),
    evidenceId: sha256(evidence.evidence_id),
    excerpt: truncatedString(evidence.excerpt, 500, ""),
    locator: boundedString(evidence.locator, 200, "unavailable"),
  };
}

function toLinkedDocumentView(value: unknown): ProgramRuleLinkedDocumentView {
  const document = record(value);
  return {
    contentType: boundedString(document.content_type, 100, "unknown"),
    kind: boundedString(document.kind, 20, "unknown"),
    normalizedSha256: sha256(document.normalized_sha256),
  };
}

function toLinkedArtifactView(value: unknown): ProgramRuleLinkedArtifactView {
  const artifact = record(value);
  return {
    evidenceIds: stringArray(artifact.evidence_ids, 100, 64).map(sha256),
    normalizedSha256: sha256(artifact.normalized_sha256),
    promotionAllowed: false,
    urlSha256: sha256(artifact.url_sha256),
  };
}

function fixedFalseAuthority(value: Record<string, unknown>): boolean {
  return permissionKeys.every((key) => value[key] === false);
}

function hasUnexpectedAuthority(value: Record<string, unknown>): boolean {
  return permissionKeys.some((key) => key in value && value[key] !== false);
}

function fixedFalsePermissionView(): FixedFalsePermissionView {
  return { ...falsePermissions };
}

function rateLimitLabel(value: unknown): string | null {
  const limit = record(value);
  if (
    !Number.isInteger(limit.requests)
    || Number(limit.requests) < 1
    || !Number.isInteger(limit.period)
    || Number(limit.period) < 1
    || !["day", "hour", "minute", "second"].includes(String(limit.unit))
  ) return null;
  const period = Number(limit.period) === 1 ? "" : ` every ${String(limit.period)}`;
  return `${String(limit.requests)} per${period} ${String(limit.unit)}`;
}

function enumValue<T extends string>(value: unknown, allowed: Set<T>, fallback: T): T {
  return typeof value === "string" && allowed.has(value as T) ? value as T : fallback;
}

function stringArray(value: unknown, maxItems: number, maxLength: number): string[] {
  return array(value, maxItems).map((item) => boundedString(item, maxLength, "needs_review"));
}

function array(value: unknown, maxItems: number): unknown[] {
  return Array.isArray(value) ? value.slice(0, maxItems) : [];
}

function boundedString(value: unknown, maxLength: number, fallback: string): string {
  return typeof value === "string" && value.length <= maxLength ? value : fallback;
}

function truncatedString(value: unknown, maxLength: number, fallback: string): string {
  return typeof value === "string" ? value.slice(0, maxLength) : fallback;
}

function nullableString(value: unknown, maxLength: number): string | null {
  return typeof value === "string" && value.length <= maxLength ? value : null;
}

function safeDate(value: unknown): string | null {
  return typeof value === "string" && value.length <= 64 && Number.isFinite(Date.parse(value))
    ? value
    : null;
}

function sha256(value: unknown): string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value) ? value : "unavailable";
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}
