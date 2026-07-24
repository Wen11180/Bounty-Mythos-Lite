const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { createProgramRuleRunner } = require("./program-rule-runner.cjs");

const CLAIM_ID = `claim_${"a".repeat(32)}`;
const SOURCE_ID = `program_rule_source_${"b".repeat(32)}`;
const TOKEN = "synthetic-claim-capability";
const ROOT = "https://rules.example.test/program";
const LINK = "https://rules.example.test/api-docs";

test("runner statically fetches one root and only returned same-origin depth-one links", async () => {
  const harness = createRunnerHarness({
    contentType: "text/html",
    normalize(document) {
      return normalized(document.source_url, document.depth, document.depth === 0 ? [
        eligible(LINK),
        eligible("https://other.example.test/rules"),
        eligible("https://rules.example.test/deeper", 2),
      ] : []);
    },
  });

  const result = await harness.runner.kick();

  assert.deepEqual(result, { next_due_at: NEXT_DUE, processed: true, status: "completed" });
  assert.equal(harness.calls.claim, 1);
  assert.deepEqual(harness.calls.fetch.map(({ allowedOrigin, method, url }) => ({
    allowedOrigin, method, url,
  })), [
    { allowedOrigin: "https://rules.example.test", method: "GET", url: ROOT },
    { allowedOrigin: "https://rules.example.test", method: "GET", url: LINK },
  ]);
  assert.deepEqual(harness.calls.fetch.map(({ aggregateBytes, documentCount }) => ({
    aggregateBytes, documentCount,
  })), [
    { aggregateBytes: 0, documentCount: 0 },
    { aggregateBytes: 32, documentCount: 1 },
  ]);
  assert.equal(harness.calls.normalize.length, 2);
  assert.equal(harness.calls.complete.length, 1);
  assert.equal(harness.calls.complete[0].documents.length, 2);
  assert.equal(harness.calls.fail.length, 0);
  assert.equal(harness.calls.createRenderer, 0);
});

test("concurrent kicks share one claim promise and idle work never creates a renderer", async () => {
  const claim = deferred();
  const harness = createRunnerHarness({ claimPromise: claim.promise });
  const first = harness.runner.kick();
  const second = harness.runner.kick();
  assert.equal(first, second);
  assert.equal(harness.calls.claim, 1);

  claim.resolve({ claim: null, next_due_at: NEXT_DUE });
  assert.deepEqual(await first, {
    next_due_at: NEXT_DUE,
    processed: false,
    status: "idle",
  });
  assert.equal(harness.calls.fetch.length, 0);
  assert.equal(harness.calls.createRenderer, 0);
});

test("only an HTML browser_render_required signal creates a fresh renderer", async () => {
  const harness = createRunnerHarness({
    contentType: "text/html",
    normalize(document) {
      if (document.mode === "static") throw codedError("browser_render_required");
      return normalized(document.source_url, document.depth);
    },
    renderResult: {
      document: browserEnvelope(ROOT, 0),
      proxy_observed: true,
    },
  });

  const result = await harness.runner.kick();

  assert.equal(result.status, "completed");
  assert.equal(harness.calls.createRenderer, 1);
  assert.deepEqual(harness.calls.render, [{ depth: 0, url: ROOT }]);
  assert.equal(harness.calls.rendererClose, 1);
  assert.deepEqual(harness.calls.normalize.map(({ document }) => document.mode), [
    "static", "browser",
  ]);
  assert.equal(harness.calls.complete.length, 1);
  assert.equal(harness.calls.fail.length, 0);
});

test("JSON fallback signals and static fetch failures never launch a browser", async () => {
  for (const scenario of ["json_fallback", "fetch_failed"]) {
    const harness = createRunnerHarness({
      contentType: "application/json",
      fetchError: scenario === "fetch_failed" ? codedError("dns_rejected") : null,
      normalize() { throw codedError("browser_render_required"); },
    });

    const result = await harness.runner.kick();

    assert.equal(result.status, "failed");
    assert.equal(harness.calls.createRenderer, 0);
    assert.equal(harness.calls.complete.length, 0);
    assert.equal(harness.calls.fail.length, 1);
    assert.equal(
      harness.calls.fail[0].failureCode,
      scenario === "fetch_failed" ? "dns_rejected" : "content_rejected",
    );
  }
});

test("runner enforces claim budgets and attempts exactly one terminal operation", async () => {
  const overBudget = createRunnerHarness({
    fetchResult(request) {
      return networkResult(request.url, request, "text/plain", 8_388_609);
    },
  });
  assert.equal((await overBudget.runner.kick()).status, "failed");
  assert.equal(overBudget.calls.complete.length, 0);
  assert.equal(overBudget.calls.fail.length, 1);
  assert.equal(overBudget.calls.fail[0].failureCode, "budget_exceeded");

  const terminalFailure = createRunnerHarness({ completeError: codedError("transport_secret") });
  assert.equal((await terminalFailure.runner.kick()).status, "failed");
  assert.equal(terminalFailure.calls.complete.length, 1);
  assert.equal(terminalFailure.calls.fail.length, 0);
});

test("close interrupts an active renderer, waits for work, and is memoized", async () => {
  const rendering = deferred();
  const rendererStarted = deferred();
  const harness = createRunnerHarness({
    contentType: "text/html",
    normalize(document) {
      if (document.mode === "static") throw codedError("browser_render_required");
      return normalized(document.source_url, document.depth);
    },
    renderer: {
      close() {
        harness.calls.rendererClose += 1;
        rendering.reject(codedError("program_rule_renderer_closed"));
        return Promise.resolve();
      },
      render(input) {
        harness.calls.render.push(input);
        rendererStarted.resolve();
        return rendering.promise;
      },
    },
  });
  const running = harness.runner.kick();
  await rendererStarted.promise;
  const firstClose = harness.runner.close("app_exit");
  const secondClose = harness.runner.close("ignored");
  assert.equal(firstClose, secondClose);

  await firstClose;
  assert.equal((await running).status, "failed");
  assert.equal(harness.calls.rendererClose, 1);
  assert.equal(harness.calls.fail.length, 1);
  await assert.rejects(harness.runner.kick(), safeRunnerError("program_rule_runner_closed"));
});

test("runner source does not log, persist, or return claim capabilities", () => {
  const source = fs.readFileSync(path.join(__dirname, "program-rule-runner.cjs"), "utf8");
  assert.doesNotMatch(source, /console\.|localStorage|writeFile|appendFile/iu);
  assert.doesNotMatch(source, /return\s+\{[^}]*claimToken/su);
});

const NEXT_DUE = "2026-07-18T12:10:00Z";

function createRunnerHarness({
  claimPromise = null,
  completeError = null,
  contentType = "text/plain",
  fetchError = null,
  fetchResult = null,
  normalize = (document) => normalized(document.source_url, document.depth),
  renderResult = null,
  renderer = null,
} = {}) {
  const calls = {
    claim: 0,
    complete: [],
    createRenderer: 0,
    fail: [],
    fetch: [],
    normalize: [],
    render: [],
    rendererClose: 0,
  };
  const apiClient = {
    async claimNext() {
      calls.claim += 1;
      return claimPromise ?? claimResult();
    },
    async complete(input) {
      calls.complete.push(input);
      if (completeError) throw completeError;
      return { snapshot_id: `snapshot_${"c".repeat(32)}` };
    },
    async fail(input) {
      calls.fail.push(input);
      return { next_check_at: NEXT_DUE };
    },
    async normalize(input) {
      calls.normalize.push(input);
      return normalize(input.document);
    },
  };
  const fallbackRenderer = renderer ?? {
    async close() { calls.rendererClose += 1; },
    async render(input) {
      calls.render.push(input);
      return renderResult;
    },
  };
  const runner = createProgramRuleRunner({
    apiClient,
    createRenderer() {
      calls.createRenderer += 1;
      return fallbackRenderer;
    },
    async fetchDocument(request) {
      calls.fetch.push(request);
      if (fetchError) throw fetchError;
      return fetchResult
        ? fetchResult(request)
        : networkResult(request.url, request, contentType);
    },
  });
  return { calls, runner };
}

function claimResult() {
  return {
    claim: {
      claim_id: CLAIM_ID,
      claim_token: TOKEN,
      expires_at: "2026-07-18T12:05:00Z",
      limits: {
        document_timeout_seconds: 10,
        max_depth: 1,
        max_document_bytes: 2_097_152,
        max_documents: 8,
        max_normalized_corpus_bytes: 2_097_152,
        max_total_bytes: 8_388_608,
      },
      source_id: SOURCE_ID,
      source_url: ROOT,
    },
    next_due_at: NEXT_DUE,
  };
}

function networkResult(url, request, contentType, aggregateBytes = request.aggregateBytes + 32) {
  const body = Buffer.alloc(32, "r");
  return {
    aggregateBytes,
    bodyBase64: body.toString("base64"),
    byteLength: body.length,
    contentType,
    documentCount: request.documentCount + 1,
    method: "GET",
    peerVerified: true,
    rawSha256: "d".repeat(64),
    statusCode: 200,
    url,
  };
}

function normalized(sourceUrl, depth, eligibleLinks = []) {
  return {
    content_type: "text/plain",
    depth,
    detected_language: "en",
    eligible_links: eligibleLinks,
    kind: "text",
    list_items: [],
    normalized_sha256: "e".repeat(64),
    openapi_like: null,
    raw_sha256: "d".repeat(64),
    source_url: sourceUrl,
    tables: [],
    visible_text: "In scope: api.example.test",
  };
}

function eligible(url, depth = 1) {
  return { depth, locator: "anchor:0", state: "eligible", text: "Rules", url };
}

function browserEnvelope(url, depth) {
  return {
    anchors: [],
    content_type: "text/html",
    depth,
    list_items: [],
    mode: "browser",
    source_url: url,
    tables: [],
    visible_strings: ["In scope: api.example.test"],
  };
}

function codedError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function deferred() {
  let reject;
  let resolve;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    reject = rejectPromise;
    resolve = resolvePromise;
  });
  return { promise, reject, resolve };
}

function safeRunnerError(code) {
  return (error) => {
    assert.equal(error?.code, code);
    assert.equal(error?.message, code);
    return true;
  };
}
