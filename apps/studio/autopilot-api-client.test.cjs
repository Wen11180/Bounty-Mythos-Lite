'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  createAutopilotApiClient,
  receiptSigningMessage,
} = require('./autopilot-api-client.cjs');

const runnerCapability = () => 'a'.repeat(43);

const capability = 'A'.repeat(43);
function jsonResponse(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let used = false;
  return {
    ok: true,
    headers: { get: (name) => name.toLowerCase() === 'content-type' ? 'application/json' : null },
    body: {
      getReader() {
        return {
          async read() {
            if (used) return { done: true, value: undefined };
            used = true;
            return { done: false, value: bytes };
          },
          async cancel() {},
          releaseLock() {},
        };
      },
    },
  };
}

test('Autopilot API client uses only campaign-bound loopback endpoints', async () => {
  const calls = [];
  const api = createAutopilotApiClient({
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return jsonResponse({ status: 'allowed' });
    },
    getBaseUrl: () => 'http://127.0.0.1:48123',
    getCapability: runnerCapability,
    getCapability: () => capability,
  });

  await api.authorize('campaign_lab', {
    lease_id: 'lease_lab',
    reservation_id: 'reservation_lab',
    method: 'GET',
    scheme: 'http',
    host: '127.0.0.1',
    port: 18080,
    path: '/api/docs/1',
  });
  await api.receipt('campaign_lab', {
    receipt: {
      schema_version: 'autopilot_transport_receipt_v1',
      receipt_id: 'receipt_lab',
      campaign_id: 'campaign_lab',
      lease_id: 'lease_lab',
      reservation_id: 'reservation_lab',
      plan_id: 'plan_lab',
      plan_digest: `sha256:${'a'.repeat(64)}`,
      branch_id: 'branch_lab',
      method: 'GET',
      scheme: 'http',
      host: '127.0.0.1',
      port: 18080,
      path: '/api/docs/1',
      body_digest: null,
      status_code: 200,
      content_type_class: 'json',
      byte_length: 10,
      sent_at: '2026-07-25T00:00:00.000Z',
      transport: 'loopback_http_v1',
      challenge: 'c'.repeat(32),
    },
  });
  await api.complete('campaign_lab', {
    reservation_id: 'reservation_lab',
    outcome: 'completed',
  });
  await api.observe('campaign_lab', {
    observation: { observation_id: 'obs_lab' },
  });
  await api.localStopStatus('campaign_lab');
  await api.acknowledgeLocalStop('campaign_lab');

  assert.deepEqual(calls.map(({ url }) => url), [
    'http://127.0.0.1:48123/mythos/campaigns/campaign_lab/autopilot/gateway/authorize',
    'http://127.0.0.1:48123/mythos/campaigns/campaign_lab/autopilot/requests/receipt',
    'http://127.0.0.1:48123/mythos/campaigns/campaign_lab/autopilot/requests/complete',
    'http://127.0.0.1:48123/mythos/campaigns/campaign_lab/autopilot/observations',
    'http://127.0.0.1:48123/mythos/campaigns/campaign_lab/autopilot/emergency-stop/local-status',
    'http://127.0.0.1:48123/mythos/campaigns/campaign_lab/autopilot/emergency-stop/local-ack',
  ]);
  assert.ok(calls.every(({ options }) => options.method === 'POST'));
  assert.ok(calls.every(({ options }) => options.redirect === 'error'));
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    lease_id: 'lease_lab',
    reservation_id: 'reservation_lab',
    method: 'GET',
    scheme: 'http',
    host: '127.0.0.1',
    port: 18080,
    path: '/api/docs/1',
  });
});

test('Autopilot API client rejects remote origins, unsafe IDs, and unsafe completion outcomes before fetch', async () => {
  const remote = createAutopilotApiClient({
    fetchImpl: async () => assert.fail('remote API must not be called'),
    getBaseUrl: () => 'https://api.example.test',
    getCapability: runnerCapability,
    getCapability: () => capability,
  });
  await assert.rejects(
    remote.authorize('campaign_lab', {}),
    /exact_loopback_api_origin_required/,
  );

  const local = createAutopilotApiClient({
    fetchImpl: async () => assert.fail('unsafe inputs must not be sent'),
    getBaseUrl: () => 'http://127.0.0.1:48123',
    getCapability: runnerCapability,
    getCapability: () => capability,
  });
  await assert.rejects(local.authorize('../campaign', {}), /autopilot_campaign_id_required/);
  await assert.rejects(
    local.complete('campaign_lab', { reservation_id: 'reservation_lab', outcome: 'sent' }),
    /autopilot_completion_outcome_required/,
  );
});

test('receipt signing preserves a zero-byte response length', () => {
  const message = receiptSigningMessage({
    schema_version: 'autopilot_transport_receipt_v1',
    receipt_id: 'receipt_lab',
    campaign_id: 'campaign_lab',
    lease_id: 'lease_lab',
    reservation_id: 'reservation_lab',
    plan_id: 'plan_lab',
    plan_digest: `sha256:${'a'.repeat(64)}`,
    branch_id: 'branch_lab',
    method: 'GET',
    scheme: 'http',
    host: '127.0.0.1',
    port: 18080,
    path: '/api/docs/1',
    body_digest: null,
    status_code: 204,
    content_type_class: 'unknown',
    byte_length: 0,
    sent_at: '2026-07-25T00:00:00.000Z',
    transport: 'loopback_http_v1',
    challenge: 'c'.repeat(32),
  });

  assert.match(message, /\n0\n/);
  assert.match(message, /\nunknown\n0\n/);
});
