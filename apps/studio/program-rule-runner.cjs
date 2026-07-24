const { canonicalPublicHttpsUrl, fetchPublicRuleDocument } = require("./program-rule-network.cjs");
const { createProgramRuleRenderer } = require("./program-rule-renderer.cjs");

const terminalFailureCodes = new Set([
  "browser_unavailable",
  "budget_exceeded",
  "content_rejected",
  "dns_rejected",
  "fetch_failed",
  "redirect_rejected",
]);
const acceptedContentTypes = new Set([
  "application/json",
  "application/x-yaml",
  "application/yaml",
  "text/html",
  "text/plain",
  "text/yaml",
]);

class ProgramRuleRunnerError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProgramRuleRunnerError";
    this.code = code;
  }
}

function createProgramRuleRunner({
  apiClient,
  createRenderer = () => createProgramRuleRenderer(),
  fetchDocument = fetchPublicRuleDocument,
} = {}) {
  if (
    !apiClient
    || typeof apiClient.claimNext !== "function"
    || typeof apiClient.complete !== "function"
    || typeof apiClient.fail !== "function"
    || typeof apiClient.normalize !== "function"
    || typeof createRenderer !== "function"
    || typeof fetchDocument !== "function"
  ) {
    throw runnerError("program_rule_runner_config_required");
  }

  let activeRenderer = null;
  const rendererClosePromises = new WeakMap();
  let closePromise = null;
  let closing = false;
  let runPromise = null;

  function kick() {
    if (closing) return Promise.reject(runnerError("program_rule_runner_closed"));
    if (runPromise !== null) return runPromise;
    const operation = runOnce();
    let tracked;
    tracked = operation.finally(() => {
      if (runPromise === tracked) runPromise = null;
    });
    runPromise = tracked;
    return tracked;
  }

  function close() {
    if (closePromise !== null) return closePromise;
    closing = true;
    closePromise = (async () => {
      if (activeRenderer !== null) {
        await closeRendererOnce(activeRenderer, "runner_close");
      }
      if (runPromise !== null) await Promise.allSettled([runPromise]);
    })();
    return closePromise;
  }

  async function runOnce() {
    let claim = null;
    let nextDueAt = null;
    let terminalAttempted = false;
    try {
      const claimed = await apiClient.claimNext();
      nextDueAt = boundedNextDue(claimed?.next_due_at);
      claim = claimed?.claim ?? null;
      if (claim === null) return status("idle", nextDueAt, false);
      assertOpen();

      const rootUrl = canonicalClaimUrl(claim.source_url);
      const origin = new URL(rootUrl).origin;
      const limits = claimLimits(claim.limits);
      let usage = { aggregateBytes: 0, documentCount: 0, normalizedBytes: 0 };
      const documents = [];

      const root = await processDocument({
        claim,
        depth: 0,
        limits,
        origin,
        url: rootUrl,
        usage,
      });
      usage = root.usage;
      documents.push(root.document);

      const seen = new Set([rootUrl]);
      for (const link of root.document.eligible_links ?? []) {
        if (usage.documentCount >= limits.maxDocuments) break;
        const url = eligibleDepthOneUrl(link, origin);
        if (url === null || seen.has(url)) continue;
        seen.add(url);
        const linked = await processDocument({
          claim,
          depth: 1,
          limits,
          origin,
          url,
          usage,
        });
        usage = linked.usage;
        documents.push(linked.document);
      }

      assertOpen();
      terminalAttempted = true;
      await apiClient.complete({
        claimId: claim.claim_id,
        claimToken: claim.claim_token,
        documents,
        sourceId: claim.source_id,
      });
      return status("completed", nextDueAt, true);
    } catch (error) {
      if (claim !== null && !terminalAttempted) {
        terminalAttempted = true;
        try {
          await apiClient.fail({
            claimId: claim.claim_id,
            claimToken: claim.claim_token,
            failureCode: failureCode(error),
            sourceId: claim.source_id,
          });
        } catch {
          // A failed local terminal call is not retried with a second operation.
        }
      }
      return status("failed", nextDueAt, claim !== null);
    }
  }

  async function processDocument({ claim, depth, limits, origin, url, usage }) {
    assertOpen();
    if (
      usage.documentCount >= limits.maxDocuments
      || usage.aggregateBytes >= limits.maxTotalBytes
    ) {
      throw runnerError("budget_exceeded");
    }

    const fetched = await fetchDocument({
      aggregateBytes: usage.aggregateBytes,
      allowedOrigin: origin,
      documentCount: usage.documentCount,
      method: "GET",
      url,
    });
    assertOpen();
    const networkUsage = validatedNetworkResult(fetched, { depth, limits, url, usage });
    const staticDocument = {
      body_base64: fetched.bodyBase64,
      charset: null,
      content_type: fetched.contentType,
      depth,
      mode: "static",
      raw_sha256: fetched.rawSha256,
      source_url: url,
    };

    let normalized;
    try {
      normalized = await apiClient.normalize({
        claimId: claim.claim_id,
        claimToken: claim.claim_token,
        document: staticDocument,
        sourceId: claim.source_id,
      });
    } catch (error) {
      if (error?.code !== "browser_render_required") throw error;
      if (fetched.contentType !== "text/html") throw runnerError("content_rejected");
      const renderer = createRenderer();
      if (
        renderer === null
        || typeof renderer !== "object"
        || typeof renderer.render !== "function"
        || typeof renderer.close !== "function"
      ) {
        throw runnerError("browser_unavailable");
      }
      activeRenderer = renderer;
      try {
        const rendered = await renderer.render({ depth, url });
        assertOpen();
        const browserDocument = rendered?.document;
        if (
          browserDocument?.mode !== "browser"
          || browserDocument.source_url !== url
          || browserDocument.depth !== depth
          || ![true, false, null].includes(rendered?.proxy_observed)
        ) {
          throw runnerError("content_rejected");
        }
        normalized = await apiClient.normalize({
          claimId: claim.claim_id,
          claimToken: claim.claim_token,
          document: browserDocument,
          sourceId: claim.source_id,
        });
      } finally {
        await closeRendererOnce(renderer, "document_complete");
        if (activeRenderer === renderer) activeRenderer = null;
      }
    }

    assertOpen();
    if (
      normalized?.source_url !== url
      || normalized?.depth !== depth
      || !Array.isArray(normalized?.eligible_links)
    ) {
      throw runnerError("content_rejected");
    }
    let normalizedBytes;
    try {
      normalizedBytes = Buffer.byteLength(JSON.stringify(normalized), "utf8");
    } catch {
      throw runnerError("content_rejected");
    }
    if (networkUsage.normalizedBytes + normalizedBytes > limits.maxNormalizedCorpusBytes) {
      throw runnerError("budget_exceeded");
    }
    return {
      document: normalized,
      usage: {
        ...networkUsage,
        normalizedBytes: networkUsage.normalizedBytes + normalizedBytes,
      },
    };
  }

  function closeRendererOnce(renderer, reason) {
    const existing = rendererClosePromises.get(renderer);
    if (existing) return existing;
    const operation = Promise.resolve().then(() => renderer.close(reason)).catch(() => {});
    rendererClosePromises.set(renderer, operation);
    return operation;
  }

  function assertOpen() {
    if (closing) throw runnerError("program_rule_runner_closed");
  }

  return { close, kick };
}

function validatedNetworkResult(value, { limits, url, usage }) {
  const decodedLength = typeof value?.bodyBase64 === "string"
    ? Buffer.from(value.bodyBase64, "base64").length
    : -1;
  if (
    value === null
    || typeof value !== "object"
    || value.url !== url
    || value.method !== "GET"
    || value.peerVerified !== true
    || value.statusCode !== 200
    || typeof value.bodyBase64 !== "string"
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value.bodyBase64)
    || typeof value.contentType !== "string"
    || !acceptedContentTypes.has(value.contentType)
    || !Number.isInteger(value.byteLength)
    || value.byteLength < 0
    || value.byteLength !== decodedLength
    || value.byteLength > limits.maxDocumentBytes
    || !Number.isInteger(value.documentCount)
    || value.documentCount !== usage.documentCount + 1
    || !Number.isInteger(value.aggregateBytes)
    || value.aggregateBytes !== usage.aggregateBytes + value.byteLength
    || value.aggregateBytes > limits.maxTotalBytes
    || !/^[0-9a-f]{64}$/u.test(value.rawSha256 ?? "")
  ) {
    throw runnerError("budget_exceeded");
  }
  return {
    aggregateBytes: value.aggregateBytes,
    documentCount: value.documentCount,
    normalizedBytes: usage.normalizedBytes,
  };
}

function eligibleDepthOneUrl(link, origin) {
  if (link?.depth !== 1 || link?.state !== "eligible" || typeof link?.url !== "string") {
    return null;
  }
  try {
    const url = canonicalPublicHttpsUrl(link.url);
    return new URL(url).origin === origin ? url : null;
  } catch {
    return null;
  }
}

function canonicalClaimUrl(value) {
  try {
    return canonicalPublicHttpsUrl(value);
  } catch {
    throw runnerError("content_rejected");
  }
}

function claimLimits(value) {
  if (
    value?.max_documents !== 8
    || value?.max_document_bytes !== 2_097_152
    || value?.max_total_bytes !== 8_388_608
    || value?.max_normalized_corpus_bytes !== 2_097_152
    || value?.document_timeout_seconds !== 10
    || value?.max_depth !== 1
  ) {
    throw runnerError("content_rejected");
  }
  return {
    maxDocumentBytes: value.max_document_bytes,
    maxDocuments: value.max_documents,
    maxNormalizedCorpusBytes: value.max_normalized_corpus_bytes,
    maxTotalBytes: value.max_total_bytes,
  };
}

function failureCode(error) {
  if (terminalFailureCodes.has(error?.code)) return error.code;
  if (error?.code === "download_rejected" || error?.code === "browser_render_required") {
    return "content_rejected";
  }
  if (error?.code === "program_rule_renderer_closed") return "fetch_failed";
  if (error?.code === "program_rule_runner_closed") return "fetch_failed";
  return "fetch_failed";
}

function boundedNextDue(value) {
  return typeof value === "string" && value.length <= 64 && Number.isFinite(Date.parse(value))
    ? value
    : null;
}

function status(value, nextDueAt, processed) {
  return { next_due_at: nextDueAt, processed, status: value };
}

function runnerError(code) {
  return new ProgramRuleRunnerError(code);
}

module.exports = { ProgramRuleRunnerError, createProgramRuleRunner };
