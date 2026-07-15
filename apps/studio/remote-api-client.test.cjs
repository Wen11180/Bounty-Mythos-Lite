const assert = require("node:assert/strict");
const test = require("node:test");

const { createRemoteLeaseApiClient } = require("./remote-api-client.cjs");

const LEASE_DIGEST = `sha256:${"a".repeat(64)}`;
const GRANT_ID = `remote_grant_${"b".repeat(32)}`;

test("remote lease API client calls only the three lease-bound loopback endpoints", async () => {
  const calls = [];
  const api = createRemoteLeaseApiClient({
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return {
        ok: true,
        async text() {
          return JSON.stringify({
            allowed: false,
            reason: "operator_stop",
            request_grant_id: null,
            stop: { reason: "operator_stop", terminal: true },
            report_submission_allowed: false,
            human_confirmation_allowed: false,
          });
        },
      };
    },
    getBaseUrl: () => "http://127.0.0.1:48123",
  });

  await api.authorize({ lease_digest: LEASE_DIGEST, request: { workflow_alias: "flow_a" } });
  await api.complete({ lease_digest: LEASE_DIGEST, outcome: "success", request_grant_id: GRANT_ID });
  await api.stop({ lease_digest: LEASE_DIGEST, reason: "operator_stop" });

  assert.deepEqual(calls.map(({ url }) => url), [
    `http://127.0.0.1:48123/mythos/studio/black-box-remote/leases/${LEASE_DIGEST}/authorize`,
    `http://127.0.0.1:48123/mythos/studio/black-box-remote/leases/${LEASE_DIGEST}/complete`,
    `http://127.0.0.1:48123/mythos/studio/black-box-remote/leases/${LEASE_DIGEST}/stop`,
  ]);
  assert.deepEqual(calls.map(({ options }) => options.method), ["POST", "POST", "POST"]);
  assert.ok(calls.every(({ options }) => options.redirect === "error"));
  assert.deepEqual(JSON.parse(calls[0].options.body), { workflow_alias: "flow_a" });
  assert.deepEqual(JSON.parse(calls[1].options.body), {
    outcome: "success",
    request_grant_id: GRANT_ID,
  });
  assert.deepEqual(JSON.parse(calls[2].options.body), { reason: "operator_stop" });
});

test("remote lease API client rejects non-loopback bases and malformed capabilities", async () => {
  const remote = createRemoteLeaseApiClient({
    fetchImpl: async () => assert.fail("fetch must remain local"),
    getBaseUrl: () => "https://api.example.test",
  });
  await assert.rejects(
    remote.stop({ lease_digest: LEASE_DIGEST, reason: "operator_stop" }),
    /exact_loopback_api_origin_required/,
  );

  const local = createRemoteLeaseApiClient({
    fetchImpl: async () => assert.fail("invalid capability must not be sent"),
    getBaseUrl: () => "http://127.0.0.1:48123",
  });
  await assert.rejects(
    local.authorize({ lease_digest: "sha256:bad", request: {} }),
    /remote_lease_digest_required/,
  );
  await assert.rejects(
    local.complete({
      lease_digest: LEASE_DIGEST,
      outcome: "success",
      request_grant_id: "bad",
    }),
    /remote_request_grant_required/,
  );
});

test("remote lease API client rejects failed or oversized local responses", async () => {
  const base = { getBaseUrl: () => "http://127.0.0.1:48123" };
  const failed = createRemoteLeaseApiClient({
    ...base,
    fetchImpl: async () => ({ ok: false, text: async () => "{}" }),
  });
  await assert.rejects(
    failed.stop({ lease_digest: LEASE_DIGEST, reason: "operator_stop" }),
    /remote_lease_api_request_failed/,
  );

  const oversized = createRemoteLeaseApiClient({
    ...base,
    fetchImpl: async () => ({ ok: true, text: async () => "x".repeat(64 * 1024 + 1) }),
  });
  await assert.rejects(
    oversized.stop({ lease_digest: LEASE_DIGEST, reason: "operator_stop" }),
    /remote_lease_api_response_too_large/,
  );
});

test("remote lease API client bounds a hung local authorization call", async () => {
  const api = createRemoteLeaseApiClient({
    fetchImpl: async (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(new Error("aborted")));
    }),
    getBaseUrl: () => "http://127.0.0.1:48123",
    timeoutMs: 5,
  });

  await assert.rejects(
    api.authorize({ lease_digest: LEASE_DIGEST, request: { workflow_alias: "flow_a" } }),
    /remote_lease_api_request_failed/,
  );
});
