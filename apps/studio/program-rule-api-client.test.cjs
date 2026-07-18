const assert = require("node:assert/strict");
const test = require("node:test");

const {
  PROGRAM_RULE_API_MAX_RESPONSE_BYTES,
  createProgramRuleApiClient,
} = require("./program-rule-api-client.cjs");

const CLAIM_ID = `claim_${"a".repeat(32)}`;
const SOURCE_ID = `program_rule_source_${"b".repeat(32)}`;
const CLAIM_TOKEN = "synthetic-claim-capability";
const SHA = "c".repeat(64);

test("program-rule API client exposes only four claim-bound loopback operations", async () => {
  const calls = [];
  const client = createProgramRuleApiClient({
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/claims/next")) return jsonResponse(claimNextResponse());
      if (url.endsWith("/normalize")) return jsonResponse(normalizedDocument());
      if (url.endsWith("/complete")) return jsonResponse(snapshotResponse());
      if (url.endsWith("/fail")) return jsonResponse(sourceResponse());
      return jsonResponse({}, { ok: false, status: 404 });
    },
    getBaseUrl: () => "http://127.0.0.1:48123",
  });

  assert.deepEqual(Object.keys(client).sort(), ["claimNext", "complete", "fail", "normalize"]);
  const claim = await client.claimNext();
  const normalized = await client.normalize({
    claimId: CLAIM_ID,
    claimToken: CLAIM_TOKEN,
    document: staticEnvelope(),
    sourceId: SOURCE_ID,
  });
  const completed = await client.complete({
    claimId: CLAIM_ID,
    claimToken: CLAIM_TOKEN,
    documents: [normalized],
    sourceId: SOURCE_ID,
  });
  const failed = await client.fail({
    claimId: CLAIM_ID,
    claimToken: CLAIM_TOKEN,
    failureCode: "content_rejected",
    sourceId: SOURCE_ID,
  });

  assert.deepEqual(claim, claimNextResponse());
  assert.deepEqual(normalized, normalizedDocument());
  assert.deepEqual(completed, snapshotResponse());
  assert.deepEqual(failed, sourceResponse());
  assert.deepEqual(calls.map(({ url }) => url), [
    "http://127.0.0.1:48123/mythos/studio/program-rule-fetch/claims/next",
    `http://127.0.0.1:48123/mythos/studio/program-rule-fetch/claims/${CLAIM_ID}/normalize`,
    `http://127.0.0.1:48123/mythos/studio/program-rule-fetch/claims/${CLAIM_ID}/complete`,
    `http://127.0.0.1:48123/mythos/studio/program-rule-fetch/claims/${CLAIM_ID}/fail`,
  ]);
  assert.ok(calls.every(({ options }) => options.method === "POST"));
  assert.ok(calls.every(({ options }) => options.redirect === "error"));
  assert.ok(calls.every(({ options }) => options.signal instanceof AbortSignal));
  assert.equal(calls[0].options.body, undefined);
  assert.equal(calls[0].options.headers, undefined);
  assert.deepEqual(JSON.parse(calls[1].options.body), {
    claim_token: CLAIM_TOKEN,
    document: staticEnvelope(),
    source_id: SOURCE_ID,
  });
  assert.deepEqual(JSON.parse(calls[2].options.body), {
    claim_token: CLAIM_TOKEN,
    documents: [normalizedDocument()],
    source_id: SOURCE_ID,
  });
  assert.deepEqual(JSON.parse(calls[3].options.body), {
    claim_token: CLAIM_TOKEN,
    failure_code: "content_rejected",
    source_id: SOURCE_ID,
  });
  assert.ok(calls.slice(1).every(({ options }) => (
    options.headers["content-type"] === "application/json"
  )));
});

test("program-rule API client rejects remote origins and malformed claim inputs before fetch", async () => {
  const remote = createProgramRuleApiClient({
    fetchImpl: async () => assert.fail("public API origin must not be called"),
    getBaseUrl: () => "https://api.example.test",
  });
  await assert.rejects(remote.claimNext(), safeApiError("exact_loopback_api_origin_required"));

  const local = createProgramRuleApiClient({
    fetchImpl: async () => assert.fail("invalid claim input must not be sent"),
    getBaseUrl: () => "http://127.0.0.1:48123",
  });
  for (const operation of [
    () => local.normalize({
      claimId: "../claim",
      claimToken: CLAIM_TOKEN,
      document: staticEnvelope(),
      sourceId: SOURCE_ID,
    }),
    () => local.complete({
      claimId: CLAIM_ID,
      claimToken: "",
      documents: [],
      sourceId: SOURCE_ID,
    }),
    () => local.fail({
      claimId: CLAIM_ID,
      claimToken: CLAIM_TOKEN,
      failureCode: "arbitrary_failure",
      sourceId: SOURCE_ID,
    }),
  ]) {
    await assert.rejects(operation(), safeApiError("program_rule_api_request_invalid"));
  }
});

test("program-rule API client recognizes only the fixed browser fallback response", async () => {
  const browserRequired = createProgramRuleApiClient({
    fetchImpl: async () => jsonResponse(
      { detail: "browser_render_required" },
      { ok: false, status: 422 },
    ),
    getBaseUrl: () => "http://127.0.0.1:48123",
  });
  await assert.rejects(
    browserRequired.normalize({
      claimId: CLAIM_ID,
      claimToken: CLAIM_TOKEN,
      document: staticEnvelope(),
      sourceId: SOURCE_ID,
    }),
    safeApiError("browser_render_required"),
  );

  const arbitrary = createProgramRuleApiClient({
    fetchImpl: async () => jsonResponse(
      { detail: "database password and raw body" },
      { ok: false, status: 422 },
    ),
    getBaseUrl: () => "http://127.0.0.1:48123",
  });
  await assert.rejects(
    arbitrary.claimNext(),
    safeApiError("program_rule_api_request_failed", ["database", "password", "raw body"]),
  );
});

test("program-rule API client rejects invalid JSON shapes, media types, and oversized streams", async () => {
  const fixtures = [
    textResponse("not-json"),
    jsonResponse({ claim: null, next_due_at: null, unexpected: true }),
    textResponse(JSON.stringify(claimNextResponse()), { contentType: "text/plain" }),
    streamingResponse([
      Buffer.alloc(PROGRAM_RULE_API_MAX_RESPONSE_BYTES),
      Buffer.from("x"),
    ]),
  ];
  for (const response of fixtures) {
    const client = createProgramRuleApiClient({
      fetchImpl: async () => response,
      getBaseUrl: () => "http://127.0.0.1:48123",
    });
    await assert.rejects(
      client.claimNext(),
      (error) => [
        "program_rule_api_response_invalid",
        "program_rule_api_response_too_large",
      ].includes(error.code),
    );
  }
});

test("program-rule API client bounds hung local calls and never leaks transport details", async () => {
  const client = createProgramRuleApiClient({
    fetchImpl: async (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener(
        "abort",
        () => reject(new Error(`Authorization: Bearer ${CLAIM_TOKEN}`)),
      );
    }),
    getBaseUrl: () => "http://127.0.0.1:48123",
    timeoutMs: 5,
  });
  await assert.rejects(
    client.claimNext(),
    safeApiError("program_rule_api_request_failed", ["Authorization", CLAIM_TOKEN]),
  );
});

test("program-rule API client sanitizes response stream failures", async () => {
  const secret = `Authorization: Bearer ${CLAIM_TOKEN}`;
  const client = createProgramRuleApiClient({
    fetchImpl: async () => ({
      body: {
        async *[Symbol.asyncIterator]() {
          throw new Error(secret);
        },
      },
      headers: { get: () => "application/json" },
      ok: true,
      status: 200,
    }),
    getBaseUrl: () => "http://127.0.0.1:48123",
  });

  await assert.rejects(
    client.claimNext(),
    safeApiError("program_rule_api_response_invalid", ["Authorization", CLAIM_TOKEN]),
  );
});

function claimNextResponse() {
  return {
    claim: {
      claim_id: CLAIM_ID,
      claim_token: CLAIM_TOKEN,
      expires_at: "2026-07-16T12:10:00Z",
      limits: {
        document_timeout_seconds: 10,
        max_depth: 1,
        max_document_bytes: 2_097_152,
        max_documents: 8,
        max_normalized_corpus_bytes: 2_097_152,
        max_total_bytes: 8_388_608,
      },
      source_id: SOURCE_ID,
      source_url: "https://rules.example.test/program",
    },
    next_due_at: "2026-07-16T12:10:00Z",
  };
}

function staticEnvelope() {
  return {
    body_base64: Buffer.from("In scope: api.example.test").toString("base64"),
    charset: "utf-8",
    content_type: "text/plain",
    depth: 0,
    mode: "static",
    raw_sha256: SHA,
    source_url: "https://rules.example.test/program",
  };
}

function normalizedDocument() {
  return {
    content_type: "text/plain",
    depth: 0,
    detected_language: "en",
    eligible_links: [],
    kind: "text",
    list_items: [],
    normalized_sha256: SHA,
    openapi_like: null,
    raw_sha256: SHA,
    source_url: "https://rules.example.test/program",
    tables: [],
    visible_text: "In scope: api.example.test",
  };
}

function snapshotResponse() {
  return {
    ai_status: "not_requested",
    artifact_warning: null,
    content_types: ["text/plain"],
    detected_language: "en",
    evidence: [],
    execution_allowed: false,
    fetched_at: "2026-07-16T12:00:00Z",
    fetch_mode: "static",
    extraction: {},
    lease_grant_allowed: false,
    linked_documents: [],
    normalized_sha256: SHA,
    openapi_candidates: [],
    raw_aggregate_sha256: SHA,
    report_submission_allowed: false,
    review_bypass_allowed: false,
    review_digest: SHA,
    review_status: "pending",
    reviewed_at: null,
    reviewer_alias: null,
    scope_change_allowed: false,
    snapshot_id: `program_rule_snapshot_${"d".repeat(32)}`,
    source_id: SOURCE_ID,
  };
}

function sourceResponse() {
  return {
    approved_snapshot_id: null,
    canonical_url: "https://rules.example.test/program",
    effective_scope_status: "needs_review",
    fetch_status: "failed",
    last_success_at: null,
    next_check_at: "2026-07-17T12:00:00Z",
    pending_snapshot_id: null,
    program_alias: "synthetic_program",
    program_id: `program_${"e".repeat(32)}`,
    registered_url: "https://rules.example.test/program",
    source_id: SOURCE_ID,
    warning: null,
  };
}

function jsonResponse(value, options = {}) {
  return textResponse(JSON.stringify(value), options);
}

function textResponse(value, {
  contentType = "application/json",
  ok = true,
  status = 200,
} = {}) {
  return {
    headers: { get: (name) => name.toLowerCase() === "content-type" ? contentType : null },
    ok,
    status,
    async text() {
      return value;
    },
  };
}

function streamingResponse(chunks) {
  return {
    body: {
      async *[Symbol.asyncIterator]() {
        for (const chunk of chunks) yield chunk;
      },
    },
    headers: { get: () => "application/json" },
    ok: true,
    status: 200,
  };
}

function safeApiError(code, forbidden = []) {
  return (error) => {
    assert.equal(error?.code, code);
    assert.equal(error?.message, code);
    const serialized = `${error?.message ?? ""} ${JSON.stringify(error)}`;
    for (const value of forbidden) assert.doesNotMatch(serialized, new RegExp(value, "u"));
    return true;
  };
}
