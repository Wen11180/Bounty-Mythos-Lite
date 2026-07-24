'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const modulePath = path.join(__dirname, 'autopilot-api-client.cjs');

test('pod grant client sends only safe IDs to the derived loopback API', async () => {
  assert.equal(fs.existsSync(modulePath), true);
  const { createAutopilotApiClient } = require(modulePath);
  const calls = [];
  const client = createAutopilotApiClient({
    getBaseUrl: () => 'http://127.0.0.1:8000',
    async fetchImpl(url, options) {
      calls.push({ url, options });
      return jsonResponse(validGrant());
    },
  });

  const grant = await client.issuePodGrant({
    campaignId: 'campaign_lab',
    podId: 'pod_lab',
    leaseId: 'lease_lab',
  });

  assert.equal(grant.grant_id, 'pod_grant_lab');
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    'http://127.0.0.1:8000/mythos/campaigns/campaign_lab/autopilot/pods/grant',
  );
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    lease_id: 'lease_lab',
    pod_id: 'pod_lab',
  });
  assert.equal(calls[0].options.redirect, 'error');
});

test('pod grant client rejects remote origins, unsafe IDs, and bad responses', async () => {
  assert.equal(fs.existsSync(modulePath), true);
  const { createAutopilotApiClient } = require(modulePath);
  for (const base of ['https://example.test', 'http://127.0.0.1:8000/path']) {
    const client = createAutopilotApiClient({
      getBaseUrl: () => base,
      fetchImpl: async () => jsonResponse(validGrant()),
    });
    await assert.rejects(
      client.issuePodGrant({ campaignId: 'c', podId: 'p', leaseId: 'l' }),
      /exact_loopback_api_origin_required/,
    );
  }

  const invalid = createAutopilotApiClient({
    getBaseUrl: () => 'http://localhost:8000',
    fetchImpl: async () => jsonResponse(validGrant()),
  });
  await assert.rejects(
    invalid.issuePodGrant({ campaignId: '../escape', podId: 'p', leaseId: 'l' }),
    /safe_autopilot_identifier_required/,
  );

  const oversized = createAutopilotApiClient({
    getBaseUrl: () => 'http://[::1]:8000',
    fetchImpl: async () => jsonResponse({ value: 'x'.repeat(40_000) }),
  });
  await assert.rejects(
    oversized.issuePodGrant({ campaignId: 'c', podId: 'p', leaseId: 'l' }),
    /autopilot_api_response_too_large/,
  );
});

function jsonResponse(value) {
  const text = JSON.stringify(value);
  return {
    ok: true,
    headers: { get: () => 'application/json' },
    text: async () => text,
  };
}

function validGrant() {
  return {
    schema_version: 'bounty-autopilot-pod-grant/v1',
    grant_id: 'pod_grant_lab',
  };
}
