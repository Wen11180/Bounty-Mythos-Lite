const assert = require("node:assert/strict");
const test = require("node:test");

const { createLocalLabDispatchHandler } = require("./local-lab-dispatch.cjs");

const completePlanDigest = `sha256:${"a".repeat(64)}`;
const leaseDigest = `sha256:${"b".repeat(64)}`;
const scopeReference = `sha256:${"c".repeat(64)}`;

function exactPreflightRequest() {
  return {
    approval_id: "approval-local",
    complete_plan: {
      lease_preview: {
        active_origin: "http://127.0.0.1:4173",
        sessions: [
          { account_alias: "account_a", ready: true, role_alias: "member", session_alias: "session_a" },
          { account_alias: "account_b", ready: true, role_alias: "member", session_alias: "session_b" },
        ],
        workflows: [{
          action: "read_only_replay",
          method: "GET",
          object_aliases: ["widget_a"],
          origin: "http://127.0.0.1:4173",
          route_template: "/widgets/{object}",
          session_alias: "session_a",
          workflow_alias: "read_widget_a",
        }],
      },
      operator_confirmed: true,
      trace_review: [{
        redacted: true,
        response_schema_fingerprint: `sha256:${"d".repeat(64)}`,
        route_template: "/widgets/{object}",
        session_alias: "session_a",
        workflow_alias: "read_widget_a",
      }],
      validation_run_id: "validation-local",
    },
    complete_plan_digest: completePlanDigest,
    lease_digest: leaseDigest,
  };
}

function approvedFacts(overrides = {}) {
  return {
    approval_id: "approval-local",
    approved_session_alias: "session_b",
    approved_workflow_alias: "read_widget_a",
    complete_plan_digest: completePlanDigest,
    execution_allowed: false,
    expires_at: "2026-07-19T01:15:00.000Z",
    lease_digest: leaseDigest,
    local_runner_dispatch_allowed: true,
    plan_digest: "plan-local",
    report_submission_allowed: false,
    scope_reference: scopeReference,
    validation_run_id: "validation-local",
    ...overrides,
  };
}

function jsonResponse(body, options = {}) {
  return {
    headers: { get: (name) => name.toLowerCase() === "content-type" ? (options.contentType ?? "application/json") : null },
    json: async () => body,
    ok: options.ok ?? true,
    status: options.status ?? 200,
  };
}

function localTrialLine(request = exactPreflightRequest()) {
  return `${JSON.stringify({
    operation: "run_trial",
    payload: {
      exact_preflight_request: request,
      session_alias: "renderer_session",
      workflow_alias: "renderer_workflow",
    },
  })}\n`;
}

test("local dispatch rejects API drift before the runner can fetch", async () => {
  let runnerCalls = 0;
  const dispatch = createLocalLabDispatchHandler({
    fetchImpl: async () => jsonResponse(
      { detail: "fresh_complete_local_plan_preflight_required" },
      { ok: false, status: 409 },
    ),
    getApiBaseUrl: () => "http://127.0.0.1:8000",
    now: () => Date.parse("2026-07-19T01:00:00.000Z"),
    runRunner: async () => {
      runnerCalls += 1;
      throw new Error("runner_must_not_run");
    },
  });

  await assert.rejects(dispatch(localTrialLine()), /fresh_local_lab_preflight_required/);
  assert.equal(runnerCalls, 0);
});

test("local preflight failure closes ephemeral sessions and permits retry after recreation", async () => {
  let sessionsOpen = true;
  let closeCalls = 0;
  let preflightCalls = 0;
  let runnerCalls = 0;
  const dispatch = createLocalLabDispatchHandler({
    closeRunnerSessions: async (reason) => {
      assert.equal(reason, "preflight_failed");
      closeCalls += 1;
      sessionsOpen = false;
    },
    fetchImpl: async () => {
      preflightCalls += 1;
      return preflightCalls === 1
        ? jsonResponse(
          { detail: "fresh_complete_local_plan_preflight_required" },
          { ok: false, status: 409 },
        )
        : jsonResponse(approvedFacts());
    },
    getApiBaseUrl: () => "http://127.0.0.1:8000",
    now: () => Date.parse("2026-07-19T01:00:00.000Z"),
    runRunner: async () => {
      assert.equal(sessionsOpen, true);
      runnerCalls += 1;
      return "runner-result";
    },
  });

  await assert.rejects(dispatch(localTrialLine()), /fresh_local_lab_preflight_required/);
  assert.equal(sessionsOpen, false);
  assert.equal(closeCalls, 1);
  assert.equal(runnerCalls, 0);

  sessionsOpen = true;
  assert.equal(await dispatch(localTrialLine()), "runner-result");
  assert.equal(closeCalls, 1);
  assert.equal(runnerCalls, 1);
});

test("local dispatch uses current server facts for exactly one runner call", async () => {
  const runnerLines = [];
  const dispatch = createLocalLabDispatchHandler({
    fetchImpl: async (url, options) => {
      assert.equal(url, "http://127.0.0.1:8000/mythos/studio/black-box-lab/runs/preflight");
      assert.equal(options.method, "POST");
      assert.deepEqual(JSON.parse(options.body), exactPreflightRequest());
      return jsonResponse(approvedFacts());
    },
    getApiBaseUrl: () => "http://127.0.0.1:8000",
    now: () => Date.parse("2026-07-19T01:00:00.000Z"),
    runRunner: async (line) => {
      runnerLines.push(JSON.parse(line));
      return "runner-result";
    },
  });

  assert.equal(await dispatch(localTrialLine()), "runner-result");
  assert.deepEqual(runnerLines, [{
    operation: "run_trial",
    payload: {
      approval_expires_at: "2026-07-19T01:15:00.000Z",
      complete_plan_digest: completePlanDigest,
      local_plan_binding: {
        active_origin: "http://127.0.0.1:4173",
        sessions: [
          { account_alias: "account_a", role_alias: "member", session_alias: "session_a" },
          { account_alias: "account_b", role_alias: "member", session_alias: "session_b" },
        ],
        workflow: {
          action: "read_only_replay",
          method: "GET",
          object_aliases: ["widget_a"],
          origin: "http://127.0.0.1:4173",
          route_template: "/widgets/{object}",
          session_alias: "session_a",
          workflow_alias: "read_widget_a",
        },
      },
      session_alias: "session_b",
      workflow_alias: "read_widget_a",
    },
  }]);
});

test("local dispatch fails closed for missing, non-loopback, non-HTTP, and non-JSON API state", async () => {
  const cases = [
    { baseUrl: null, fetchImpl: async () => jsonResponse(approvedFacts()) },
    { baseUrl: "http://example.test:8000", fetchImpl: async () => jsonResponse(approvedFacts()) },
    { baseUrl: "https://127.0.0.1:8000", fetchImpl: async () => jsonResponse(approvedFacts()) },
    {
      baseUrl: "http://127.0.0.1:8000",
      fetchImpl: async () => jsonResponse(approvedFacts(), { contentType: "text/html" }),
    },
  ];

  for (const fixture of cases) {
    let runnerCalls = 0;
    const dispatch = createLocalLabDispatchHandler({
      fetchImpl: fixture.fetchImpl,
      getApiBaseUrl: () => fixture.baseUrl,
      now: () => Date.parse("2026-07-19T01:00:00.000Z"),
      runRunner: async () => { runnerCalls += 1; },
    });
    await assert.rejects(dispatch(localTrialLine()), /fresh_local_lab_preflight_required/);
    assert.equal(runnerCalls, 0);
  }
});

test("local dispatch rejects expired or mismatched facts before runner invocation", async () => {
  for (const facts of [
    approvedFacts({ expires_at: "2026-07-19T01:00:00.000Z" }),
    approvedFacts({ complete_plan_digest: `sha256:${"0".repeat(64)}` }),
    approvedFacts({ approved_session_alias: "session_changed" }),
    approvedFacts({ execution_allowed: true }),
  ]) {
    let runnerCalls = 0;
    const dispatch = createLocalLabDispatchHandler({
      fetchImpl: async () => jsonResponse(facts),
      getApiBaseUrl: () => "http://127.0.0.1:8000",
      now: () => Date.parse("2026-07-19T01:00:00.000Z"),
      runRunner: async () => { runnerCalls += 1; },
    });
    await assert.rejects(dispatch(localTrialLine()), /fresh_local_lab_preflight_required/);
    assert.equal(runnerCalls, 0);
  }
});

test("navigation cleanup while exact preflight is pending prevents runner dispatch", async () => {
  let resolvePreflight;
  let enteredPreflight;
  const entered = new Promise((resolve) => { enteredPreflight = resolve; });
  const pendingResponse = new Promise((resolve) => { resolvePreflight = resolve; });
  let current = true;
  let runnerCalls = 0;
  const dispatch = createLocalLabDispatchHandler({
    fetchImpl: async () => {
      enteredPreflight();
      return pendingResponse;
    },
    getApiBaseUrl: () => "http://127.0.0.1:8000",
    now: () => Date.parse("2026-07-19T01:00:00.000Z"),
    runRunner: async () => { runnerCalls += 1; },
  });

  const result = dispatch(localTrialLine(), { isCurrent: () => current });
  await entered;
  current = false;
  resolvePreflight(jsonResponse(approvedFacts()));

  await assert.rejects(result, /local_lab_dispatch_cancelled/);
  assert.equal(runnerCalls, 0);
});

test("remote runner messages preserve existing semantics without local preflight", async () => {
  const line = `${JSON.stringify({
    operation: "run_trial",
    payload: { session_alias: "session_b", trial_class: "cross_account_read", workflow_alias: "read_widget_a" },
  })}\n`;
  let fetchCalls = 0;
  const dispatch = createLocalLabDispatchHandler({
    fetchImpl: async () => { fetchCalls += 1; },
    getApiBaseUrl: () => null,
    runRunner: async (value) => value,
  });

  assert.equal(await dispatch(line), line);
  assert.equal(fetchCalls, 0);
});
