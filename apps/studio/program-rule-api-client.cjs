const { canonicalPublicHttpsUrl } = require("./program-rule-network.cjs");

const PROGRAM_RULE_API_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const PROGRAM_RULE_API_MAX_REQUEST_BYTES = 12 * 1024 * 1024;
const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
const failureCodes = new Set([
  "browser_unavailable",
  "budget_exceeded",
  "content_rejected",
  "dns_rejected",
  "fetch_failed",
  "redirect_rejected",
]);
const sha256Pattern = /^[0-9a-f]{64}$/u;
const safeIdPattern = /^[A-Za-z0-9_-]{1,128}$/u;

class ProgramRuleApiError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProgramRuleApiError";
    this.code = code;
  }
}

function createProgramRuleApiClient({
  fetchImpl = globalThis.fetch,
  getBaseUrl,
  timeoutMs = 5_000,
} = {}) {
  if (
    typeof fetchImpl !== "function"
    || typeof getBaseUrl !== "function"
    || !Number.isInteger(timeoutMs)
    || timeoutMs < 1
    || timeoutMs > 10_000
  ) {
    throw apiError("program_rule_api_client_config_required");
  }

  async function post(path, payload, responseKind) {
    const origin = exactLoopbackApiOrigin(getBaseUrl());
    let options = {
      method: "POST",
      redirect: "error",
    };
    if (payload !== undefined) {
      let body;
      try {
        body = JSON.stringify(payload);
      } catch {
        throw apiError("program_rule_api_request_invalid");
      }
      if (Buffer.byteLength(body, "utf8") > PROGRAM_RULE_API_MAX_REQUEST_BYTES) {
        throw apiError("program_rule_api_request_invalid");
      }
      options = {
        ...options,
        body,
        headers: { "content-type": "application/json" },
      };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      let response;
      try {
        response = await fetchImpl(`${origin}${path}`, { ...options, signal: controller.signal });
      } catch {
        throw apiError("program_rule_api_request_failed");
      }
      let responseOk;
      let responseStatus;
      try {
        responseOk = response?.ok === true;
        responseStatus = response?.status;
      } catch {
        throw apiError("program_rule_api_request_failed");
      }
      if (!responseOk) {
        if (responseKind === "normalized" && responseStatus === 422) {
          try {
            const detail = await readJsonResponse(response);
            if (
              hasExactKeys(detail, ["detail"])
              && detail.detail === "browser_render_required"
            ) {
              throw apiError("browser_render_required");
            }
          } catch (error) {
            if (error instanceof ProgramRuleApiError && error.code === "browser_render_required") {
              throw error;
            }
          }
        }
        throw apiError("program_rule_api_request_failed");
      }

      const parsed = await readJsonResponse(response);
      if (!validateResponse(responseKind, parsed)) {
        throw apiError("program_rule_api_response_invalid");
      }
      return parsed;
    } finally {
      clearTimeout(timeout);
    }
  }

  return {
    async claimNext() {
      return post(
        "/mythos/studio/program-rule-fetch/claims/next",
        undefined,
        "claim",
      );
    },
    async complete({ claimId, claimToken, documents, sourceId } = {}) {
      if (
        !isClaimInput(claimId, claimToken, sourceId)
        || !Array.isArray(documents)
        || documents.length < 1
        || documents.length > 8
        || !documents.every(isNormalizedDocument)
      ) {
        throw apiError("program_rule_api_request_invalid");
      }
      return post(
        `/mythos/studio/program-rule-fetch/claims/${claimId}/complete`,
        { claim_token: claimToken, documents, source_id: sourceId },
        "snapshot",
      );
    },
    async fail({ claimId, claimToken, failureCode, sourceId } = {}) {
      if (!isClaimInput(claimId, claimToken, sourceId) || !failureCodes.has(failureCode)) {
        throw apiError("program_rule_api_request_invalid");
      }
      return post(
        `/mythos/studio/program-rule-fetch/claims/${claimId}/fail`,
        { claim_token: claimToken, failure_code: failureCode, source_id: sourceId },
        "source",
      );
    },
    async normalize({ claimId, claimToken, document, sourceId } = {}) {
      if (!isClaimInput(claimId, claimToken, sourceId) || !isDocumentEnvelope(document)) {
        throw apiError("program_rule_api_request_invalid");
      }
      return post(
        `/mythos/studio/program-rule-fetch/claims/${claimId}/normalize`,
        { claim_token: claimToken, document, source_id: sourceId },
        "normalized",
      );
    },
  };
}

function exactLoopbackApiOrigin(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw apiError("exact_loopback_api_origin_required");
  }
  if (
    typeof value !== "string"
    || parsed.protocol !== "http:"
    || !loopbackHosts.has(parsed.hostname)
    || parsed.username
    || parsed.password
    || value !== parsed.origin
  ) {
    throw apiError("exact_loopback_api_origin_required");
  }
  return parsed.origin;
}

async function readJsonResponse(response) {
  let contentType;
  try {
    contentType = response?.headers?.get?.("content-type");
  } catch {
    throw apiError("program_rule_api_response_invalid");
  }
  if (
    typeof contentType !== "string"
    || !/^application\/json(?:\s*;\s*charset=[A-Za-z0-9._-]+)?$/iu.test(contentType.trim())
  ) {
    throw apiError("program_rule_api_response_invalid");
  }
  let bytes;
  try {
    bytes = await readBoundedBody(response);
  } catch (error) {
    if (error instanceof ProgramRuleApiError) throw error;
    throw apiError("program_rule_api_response_invalid");
  }
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw apiError("program_rule_api_response_invalid");
  }
}

async function readBoundedBody(response) {
  const chunks = [];
  let total = 0;
  const append = (value) => {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    total += chunk.length;
    if (total > PROGRAM_RULE_API_MAX_RESPONSE_BYTES) {
      throw apiError("program_rule_api_response_too_large");
    }
    chunks.push(chunk);
  };

  const body = response?.body;
  if (body && typeof body[Symbol.asyncIterator] === "function") {
    for await (const chunk of body) append(chunk);
  } else if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        append(value);
      }
    } finally {
      reader.releaseLock?.();
    }
  } else if (typeof response?.text === "function") {
    append(await response.text());
  } else {
    throw apiError("program_rule_api_response_invalid");
  }
  return Buffer.concat(chunks, total);
}

function validateResponse(kind, value) {
  if (kind === "claim") return isClaimNext(value);
  if (kind === "normalized") return isNormalizedDocument(value);
  if (kind === "snapshot") return isSnapshot(value);
  if (kind === "source") return isSource(value);
  return false;
}

function isClaimNext(value) {
  if (!hasExactKeys(value, ["claim", "next_due_at"]) || !isNullableDate(value.next_due_at)) {
    return false;
  }
  if (value.claim === null) return true;
  const claim = value.claim;
  return (
    hasExactKeys(claim, [
      "claim_id", "claim_token", "expires_at", "limits", "source_id", "source_url",
    ])
    && safeIdPattern.test(claim.claim_id)
    && isBoundedString(claim.claim_token, 1, 512)
    && isDate(claim.expires_at)
    && safeIdPattern.test(claim.source_id)
    && isPublicUrl(claim.source_url)
    && hasExactKeys(claim.limits, [
      "document_timeout_seconds", "max_depth", "max_document_bytes", "max_documents",
      "max_normalized_corpus_bytes", "max_total_bytes",
    ])
    && claim.limits.document_timeout_seconds === 10
    && claim.limits.max_depth === 1
    && claim.limits.max_document_bytes === 2_097_152
    && claim.limits.max_documents === 8
    && claim.limits.max_normalized_corpus_bytes === 2_097_152
    && claim.limits.max_total_bytes === 8_388_608
  );
}

function isClaimInput(claimId, claimToken, sourceId) {
  return (
    typeof claimId === "string"
    && safeIdPattern.test(claimId)
    && isBoundedString(claimToken, 1, 512)
    && typeof sourceId === "string"
    && safeIdPattern.test(sourceId)
  );
}

function isDocumentEnvelope(value) {
  if (!isRecord(value) || !isPublicUrl(value.source_url) || ![0, 1].includes(value.depth)) {
    return false;
  }
  if (!isBoundedString(value.content_type, 1, 100)) return false;
  if (value.mode === "static") {
    return (
      hasExactKeys(value, [
        "body_base64", "charset", "content_type", "depth", "mode", "raw_sha256",
        "source_url",
      ])
      && isBoundedString(value.body_base64, 1, 3_000_000)
      && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value.body_base64)
      && (value.charset === null || value.charset === undefined || isBoundedString(value.charset, 0, 40))
      && sha256Pattern.test(value.raw_sha256)
    );
  }
  if (value.mode === "browser") {
    return (
      hasExactKeys(value, [
        "anchors", "content_type", "depth", "list_items", "mode", "source_url", "tables",
        "visible_strings",
      ])
      && isProjectionStrings(value.visible_strings, 4_000)
      && isProjectionStrings(value.list_items, 4_000)
      && isTables(value.tables)
      && Array.isArray(value.anchors)
      && value.anchors.length <= 500
      && value.anchors.every((anchor) => (
        hasExactKeys(anchor, ["href", "is_attachment", "text"])
        && isBoundedString(anchor.text, 0, 8_192)
        && isBoundedString(anchor.href, 1, 2_048)
        && typeof anchor.is_attachment === "boolean"
      ))
    );
  }
  return false;
}

function isNormalizedDocument(value) {
  return (
    hasExactKeys(value, [
      "content_type", "depth", "detected_language", "eligible_links", "kind", "list_items",
      "normalized_sha256", "openapi_like", "raw_sha256", "source_url", "tables", "visible_text",
    ])
    && isPublicUrl(value.source_url)
    && [0, 1].includes(value.depth)
    && ["html", "json", "text", "yaml"].includes(value.kind)
    && isBoundedString(value.content_type, 1, 100)
    && (value.raw_sha256 === null || sha256Pattern.test(value.raw_sha256))
    && sha256Pattern.test(value.normalized_sha256)
    && ["en", "unsupported"].includes(value.detected_language)
    && isBoundedString(value.visible_text, 0, 524_288)
    && isTables(value.tables)
    && isProjectionStrings(value.list_items, 4_000)
    && Array.isArray(value.eligible_links)
    && value.eligible_links.length <= 500
    && value.eligible_links.every(isEligibleLink)
    && (value.openapi_like === null || isSafeJson(value.openapi_like))
  );
}

function isEligibleLink(value) {
  return (
    hasExactKeys(value, ["depth", "locator", "state", "text", "url"])
    && value.state === "eligible"
    && value.depth === 1
    && isPublicUrl(value.url)
    && isBoundedString(value.text, 0, 500)
    && isBoundedString(value.locator, 1, 200)
  );
}

function isSnapshot(value) {
  return (
    hasExactKeys(value, [
      "ai_status", "artifact_warning", "content_types", "detected_language", "evidence",
      "execution_allowed", "fetched_at", "fetch_mode", "extraction", "lease_grant_allowed",
      "linked_documents", "normalized_sha256", "openapi_candidates", "raw_aggregate_sha256",
      "report_submission_allowed", "review_bypass_allowed", "review_digest", "review_status",
      "reviewed_at", "reviewer_alias", "scope_change_allowed", "snapshot_id", "source_id",
    ])
    && safeIdPattern.test(value.snapshot_id)
    && safeIdPattern.test(value.source_id)
    && sha256Pattern.test(value.raw_aggregate_sha256)
    && sha256Pattern.test(value.normalized_sha256)
    && sha256Pattern.test(value.review_digest)
    && isDate(value.fetched_at)
    && isBoundedString(value.fetch_mode, 1, 50)
    && isStringArray(value.content_types, 100)
    && isBoundedString(value.detected_language, 1, 50)
    && isSafeJson(value.extraction)
    && isSafeJson(value.evidence)
    && isSafeJson(value.linked_documents)
    && isSafeJson(value.openapi_candidates)
    && ["not_requested", "ok", "rejected", "unavailable"].includes(value.ai_status)
    && ["approved", "pending", "rejected"].includes(value.review_status)
    && (value.reviewer_alias === null || isBoundedString(value.reviewer_alias, 1, 100))
    && isNullableDate(value.reviewed_at)
    && [null, "openapi_promotion_pending"].includes(value.artifact_warning)
    && hasFalsePermissions(value)
  );
}

function isSource(value) {
  return (
    hasExactKeys(value, [
      "approved_snapshot_id", "canonical_url", "effective_scope_status", "fetch_status",
      "last_success_at", "next_check_at", "pending_snapshot_id", "program_alias", "program_id",
      "registered_url", "source_id", "warning",
    ])
    && safeIdPattern.test(value.source_id)
    && (value.program_id === null || safeIdPattern.test(value.program_id))
    && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(value.program_alias)
    && isPublicUrl(value.registered_url)
    && isPublicUrl(value.canonical_url)
    && ["browser_render_required", "failed", "fetching", "ok", "scheduled"].includes(value.fetch_status)
    && ["active", "frozen", "needs_review"].includes(value.effective_scope_status)
    && (value.warning === null || isBoundedString(value.warning, 0, 500))
    && isNullableDate(value.last_success_at)
    && isDate(value.next_check_at)
    && (value.approved_snapshot_id === null || safeIdPattern.test(value.approved_snapshot_id))
    && (value.pending_snapshot_id === null || safeIdPattern.test(value.pending_snapshot_id))
  );
}

function hasFalsePermissions(value) {
  return [
    "execution_allowed",
    "lease_grant_allowed",
    "report_submission_allowed",
    "review_bypass_allowed",
    "scope_change_allowed",
  ].every((key) => value[key] === false);
}

function isPublicUrl(value) {
  try {
    return canonicalPublicHttpsUrl(value) === value;
  } catch {
    return false;
  }
}

function isProjectionStrings(value, maxItems) {
  return Array.isArray(value) && value.length <= maxItems
    && value.every((item) => isBoundedString(item, 0, 8_192));
}

function isTables(value) {
  return Array.isArray(value) && value.length <= 64 && value.every((table) => (
    Array.isArray(table) && table.length <= 256 && table.every((row) => (
      Array.isArray(row) && row.length <= 64
      && row.every((cell) => isBoundedString(cell, 0, 8_192))
    ))
  ));
}

function isStringArray(value, maxLength) {
  return Array.isArray(value) && value.length <= 100
    && value.every((item) => isBoundedString(item, 0, maxLength));
}

function isSafeJson(value, depth = 0, budget = { nodes: 20_000 }) {
  if (budget.nodes-- < 1 || depth > 32) return false;
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) {
    return value.length <= 10_000 && value.every((item) => isSafeJson(item, depth + 1, budget));
  }
  if (!isRecord(value) || Object.keys(value).length > 10_000) return false;
  return Object.values(value).every((item) => isSafeJson(item, depth + 1, budget));
}

function hasExactKeys(value, keys) {
  return isRecord(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isBoundedString(value, min, max) {
  return typeof value === "string" && value.length >= min && value.length <= max;
}

function isDate(value) {
  return isBoundedString(value, 1, 64) && Number.isFinite(Date.parse(value));
}

function isNullableDate(value) {
  return value === null || isDate(value);
}

function apiError(code) {
  return new ProgramRuleApiError(code);
}

module.exports = {
  PROGRAM_RULE_API_MAX_RESPONSE_BYTES,
  ProgramRuleApiError,
  createProgramRuleApiClient,
};
