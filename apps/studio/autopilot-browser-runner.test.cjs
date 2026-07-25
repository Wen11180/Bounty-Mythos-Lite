'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');

const {
  createAutopilotBrowserRunner,
  executeBoundHttpRequest,
} = require('./autopilot-browser-runner.cjs');
const { createAutopilotApiClient } = require('./autopilot-api-client.cjs');

const PLAN_DIGEST = `sha256:${'a'.repeat(64)}`;

function binding(overrides = {}) {
  return {
    campaign_id: 'campaign_lab',
    lease_id: 'lease_lab',
    reservation_id: 'reservation_lab',
    plan_id: 'plan_lab',
    plan_digest: PLAN_DIGEST,
    branch_id: 'branch_lab',
    recipe_id: 'lab_browser_mapping',
    recipe_version: '1.0',
    policy_mode: 'authorized_local_lab',
    scheme: 'http',
    host: '127.0.0.1',
    port: 18080,
    path: '/api/docs/1',
    method: 'GET',
    account_alias: null,
    max_response_bytes: 128,
    max_duration_seconds: 5,
    admitted_ips: ['127.0.0.1'],
    transport_challenge: 'c'.repeat(32),
    ...overrides,
  };
}

function request(overrides = {}) {
  return {
    campaignId: 'campaign_lab',
    leaseId: 'lease_lab',
    reservationId: 'reservation_lab',
    method: 'GET',
    scheme: 'http',
    host: '127.0.0.1',
    port: 18080,
    path: '/api/docs/1',
    ...overrides,
  };
}

function runnerFixture({
  gateway = {
    status: 'allowed',
    transport_challenge: 'c'.repeat(32),
    execution_binding: binding(),
  },
  resolvedIps = ['127.0.0.1'],
  target = {
    byteLength: 24,
    contentType: 'application/json',
    statusCode: 200,
  },
} = {}) {
  const calls = [];
  const runner = createAutopilotBrowserRunner({
    apiClient: {
      authorize: async (campaignId, payload) => {
        calls.push({ kind: 'authorize', campaignId, payload });
        return gateway;
      },
      complete: async (campaignId, payload) => {
        calls.push({ kind: 'complete', campaignId, payload });
      },
      receipt: async (campaignId, payload) => {
        calls.push({ kind: 'receipt', campaignId, payload });
        return { receipt_digest: `sha256:${'b'.repeat(64)}` };
      },
      observe: async (campaignId, payload) => {
        calls.push({ kind: 'observe', campaignId, payload });
      },
    },
    createObservationId: () => 'obs_runner',
    assertPodStart: ({ gateway, binding: executionBinding }) => ({
      ok: gateway.status === 'allowed' && executionBinding.policy_mode === 'authorized_local_lab',
      reason: 'gateway_authorization_required',
    }),
    executeRequest: async (executionBinding, resolvedIp) => {
      calls.push({ kind: 'target', executionBinding, resolvedIp });
      return target;
    },
    resolveHost: async () => resolvedIps,
  });
  return { calls, runner };
}

test('runner uses the server binding, discards the body, then completes and persists metadata only', async () => {
  const { calls, runner } = runnerFixture();

  const result = await runner.run(request());

  assert.deepEqual(calls.map((call) => call.kind), [
    'authorize',
    'target',
    'receipt',
    'complete',
    'observe',
  ]);
  assert.deepEqual(calls[0].payload, {
    lease_id: 'lease_lab',
    reservation_id: 'reservation_lab',
    method: 'GET',
    scheme: 'http',
    host: '127.0.0.1',
    port: 18080,
    path: '/api/docs/1',
  });
  assert.equal(calls[1].executionBinding.path, '/api/docs/1');
  assert.equal(calls[2].payload.receipt.content_type_class, 'json');
  assert.deepEqual(calls[3].payload, {
    reservation_id: 'reservation_lab',
    outcome: 'completed',
  });
  assert.deepEqual(calls[4].payload, {
    observation: {
      observation_id: 'obs_runner',
      branch_id: 'branch_lab',
      plan_digest: PLAN_DIGEST,
      lease_id: 'lease_lab',
      reservation_id: 'reservation_lab',
      receipt_digest: `sha256:${'b'.repeat(64)}`,
      grade: 'L1_hint',
      outcome_class: 'ok',
      summary: 'metadata_only_response:2xx:json',
      evidence_refs: ['metadata_only_response'],
      status_class: '2xx',
      content_type_class: 'json',
      byte_length: 24,
      third_party_data_discarded: false,
    },
  });
  assert.deepEqual(result, {
    status: 'completed',
    outcome_class: 'ok',
    status_class: '2xx',
    content_type_class: 'json',
    byte_length: 24,
    third_party_data_discarded: false,
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
  });
  assert.doesNotMatch(JSON.stringify(result), /docs|127\.0\.0\.1|body|header/i);
});

test('a server binding mismatch performs zero target requests and closes the sent reservation as no-send', async () => {
  const { calls, runner } = runnerFixture({
    gateway: {
      status: 'allowed',
      transport_challenge: 'c'.repeat(32),
      execution_binding: binding({ path: '/api/docs/2' }),
    },
  });

  await assert.rejects(runner.run(request()), /execution_binding_mismatch/);

  assert.deepEqual(calls.map((call) => call.kind), ['authorize', 'complete']);
  assert.deepEqual(calls[1].payload, {
    reservation_id: 'reservation_lab',
    outcome: 'no_send_failure',
  });
});

test('a Gateway-bound pod rejection performs zero target requests and closes the reservation', async () => {
  const calls = [];
  const runner = createAutopilotBrowserRunner({
    apiClient: {
      authorize: async () => ({
        status: 'allowed',
        transport_challenge: 'c'.repeat(32),
        execution_binding: binding(),
      }),
      complete: async (_campaignId, payload) => calls.push(payload),
      receipt: async () => ({ receipt_digest: PLAN_DIGEST }),
      observe: async () => {},
    },
    assertPodStart: () => ({ ok: false, reason: 'worker_isolation_required' }),
    executeRequest: async () => {
      throw new Error('target_must_not_run');
    },
    resolveHost: async () => ['127.0.0.1'],
  });

  await assert.rejects(runner.run(request()), /worker_isolation_required/);
  assert.deepEqual(calls, [{ reservation_id: 'reservation_lab', outcome: 'no_send_failure' }]);
});

test('DNS drift performs zero target requests, records a sanitized stop, and never returns the address', async () => {
  const { calls, runner } = runnerFixture({ resolvedIps: ['127.0.0.2'] });

  const result = await runner.run(request());

  assert.deepEqual(calls.map((call) => call.kind), ['authorize', 'complete', 'observe']);
  assert.deepEqual(calls[1].payload, {
    reservation_id: 'reservation_lab',
    outcome: 'no_send_failure',
  });
  assert.equal(calls[2].payload.observation.outcome_class, 'dns_rebind');
  assert.deepEqual(result, {
    status: 'blocked',
    outcome_class: 'dns_rebind',
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
  });
  assert.doesNotMatch(JSON.stringify(result), /127\.0\.0\.2/);
});

test('redirect, rate limit, WAF, third-party, and response-size outcomes terminate after one discarded response', async (t) => {
  const cases = [
    ['redirect', { statusCode: 302, contentType: 'text/html', byteLength: 8, isRedirect: true }, 'off_scope_redirect', false],
    ['rate limit', { statusCode: 429, contentType: 'application/json', byteLength: 8 }, 'rate_limit', false],
    ['WAF', { statusCode: 403, contentType: 'text/html', byteLength: 8, wafDetected: true }, 'waf_captcha', false],
    ['third party', { statusCode: 200, contentType: 'application/json', byteLength: 8, thirdPartyDetected: true }, 'third_party_data', true],
    ['size ceiling', { statusCode: 200, contentType: 'application/json', byteLength: 129 }, 'size_ceiling', false],
  ];

  for (const [name, target, expectedOutcome, discarded] of cases) {
    await t.test(name, async () => {
      const { calls, runner } = runnerFixture({ target });
      const result = await runner.run(request());

      assert.deepEqual(calls.map((call) => call.kind), [
        'authorize',
        'target',
        'receipt',
        'complete',
        'observe',
      ]);
      assert.equal(calls[3].payload.outcome, 'completed');
      assert.equal(calls[4].payload.observation.outcome_class, expectedOutcome);
      assert.equal(calls[4].payload.observation.third_party_data_discarded, discarded);
      assert.equal(result.outcome_class, expectedOutcome);
      assert.equal(result.third_party_data_discarded, discarded);
      assert.doesNotMatch(JSON.stringify(result), /body|header|location/i);
    });
  }
});

test('bound HTTP execution streams and discards bytes without returning response content or redirect location', async () => {
  const server = http.createServer((req, response) => {
    if (req.url === '/redirect') {
      response.writeHead(302, { location: 'http://example.invalid/never-followed' });
      response.end('redirect-secret');
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"sensitive":"never-returned"}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  try {
    const normal = await executeBoundHttpRequest(
      binding({ port, max_response_bytes: 1024 }),
      '127.0.0.1',
    );
    assert.deepEqual(normal, {
      statusCode: 200,
      contentType: 'application/json',
      byteLength: 30,
      isRedirect: false,
      wafDetected: false,
      thirdPartyDetected: false,
    });
    assert.doesNotMatch(JSON.stringify(normal), /sensitive|never-returned/);

    const redirected = await executeBoundHttpRequest(
      binding({ path: '/redirect', port, max_response_bytes: 1024 }),
      '127.0.0.1',
    );
    assert.equal(redirected.statusCode, 302);
    assert.equal(redirected.isRedirect, true);
    assert.doesNotMatch(JSON.stringify(redirected), /example|secret|location/i);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('full Loopback trace uses gateway binding and persists only response metadata', async () => {
  const targetBody = '{"authorization":"Bearer body-must-not-persist"}';
  let targetRequests = 0;
  const target = http.createServer((_request, response) => {
    targetRequests += 1;
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(targetBody);
  });
  await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
  const targetPort = target.address().port;
  const traces = [];
  const control = http.createServer(async (req, response) => {
    const body = await readRequestBody(req);
    traces.push({ path: req.url, body: JSON.parse(body) });
    let payload;
    if (req.url.endsWith('/gateway/authorize')) {
      payload = {
        status: 'allowed',
        transport_challenge: 'c'.repeat(32),
        execution_binding: binding({ port: targetPort }),
      };
    } else if (req.url.endsWith('/requests/receipt')) {
      payload = { status: 'sent', receipt_digest: `sha256:${'b'.repeat(64)}` };
    } else if (req.url.endsWith('/requests/complete')) {
      payload = { status: 'completed' };
    } else if (req.url.endsWith('/observations')) {
      payload = { observation_id: 'obs_full_trace' };
    } else {
      response.writeHead(404);
      response.end('{}');
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload));
  });
  await new Promise((resolve) => control.listen(0, '127.0.0.1', resolve));
  const controlPort = control.address().port;

  try {
    const runner = createAutopilotBrowserRunner({
      apiClient: createAutopilotApiClient({
        getBaseUrl: () => `http://127.0.0.1:${controlPort}`,
        getCapability: () => 'A'.repeat(43),
        getCapability: () => 'a'.repeat(43),
      }),
      createObservationId: () => 'obs_full_trace',
      assertPodStart: ({ gateway, binding: executionBinding }) => ({
        ok: gateway.status === 'allowed' && executionBinding.policy_mode === 'authorized_local_lab',
      }),
    });
    const result = await runner.run(request({ port: targetPort }));

    assert.equal(targetRequests, 1);
    assert.deepEqual(traces.map((trace) => trace.path), [
      '/mythos/campaigns/campaign_lab/autopilot/gateway/authorize',
      '/mythos/campaigns/campaign_lab/autopilot/requests/receipt',
      '/mythos/campaigns/campaign_lab/autopilot/requests/complete',
      '/mythos/campaigns/campaign_lab/autopilot/observations',
    ]);
    assert.equal(traces[1].body.receipt.content_type_class, 'json');
    assert.equal(traces[3].body.observation.status_class, '2xx');
    assert.equal(traces[3].body.observation.content_type_class, 'json');
    assert.equal(traces[3].body.observation.byte_length, Buffer.byteLength(targetBody));
    assert.doesNotMatch(JSON.stringify(traces[3].body), /Bearer|body-must-not-persist|authorization/i);
    assert.doesNotMatch(JSON.stringify(result), /Bearer|body-must-not-persist|authorization/i);
  } finally {
    await new Promise((resolve) => control.close(resolve));
    await new Promise((resolve) => target.close(resolve));
  }
});

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.once('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.once('error', reject);
  });
}
