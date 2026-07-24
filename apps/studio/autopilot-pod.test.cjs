'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  assertLabPodStart,
  blockUnsupportedProtocol,
  detectIsolationAvailability,
  inspectPodResponse,
} = require('./autopilot-pod.cjs');

test('pod starts only from an exact current server grant and verified isolation', () => {
  assert.equal(
    assertLabPodStart({
      policyMode: 'authorized_local_lab',
      leaseActive: true,
      campaignAuthorized: true,
      dockerAvailable: true,
    }).reason,
    'server_pod_grant_required',
  );
  assert.equal(
    assertLabPodStart({
      grant: validGrant({ policy_mode: 'public' }),
      dockerAvailable: true,
      now: '2026-07-24T01:01:00.000Z',
    }).reason,
    'policy_mode_blocks_active_execution',
  );
  assert.equal(
    assertLabPodStart({
      grant: validGrant({ lease_status: 'revoked' }),
      dockerAvailable: true,
      now: '2026-07-24T01:01:00.000Z',
    }).reason,
    'lease_inactive',
  );
  assert.equal(
    assertLabPodStart({
      grant: validGrant(),
      isolationRequired: true,
      dockerAvailable: false,
      wslAvailable: false,
      now: '2026-07-24T01:01:00.000Z',
    }).reason,
    'isolation_unavailable',
  );
  assert.equal(
    assertLabPodStart({
      grant: validGrant({ expires_at: '2026-07-24T01:00:59.000Z' }),
      dockerAvailable: true,
      now: '2026-07-24T01:01:00.000Z',
    }).reason,
    'pod_grant_expired',
  );

  const started = assertLabPodStart({
    grant: validGrant(),
    dockerAvailable: true,
    now: '2026-07-24T01:01:00.000Z',
  });
  assert.equal(started.ok, true);
  assert.equal(started.reason, 'started');
  assert.equal(started.grant.campaign_id, 'campaign_lab');
  assert.equal(started.grant.lease_id, 'lease_lab');
  assert.equal(Object.isFrozen(started.grant), true);
});

test('grant rejects extra fields, secrets, or unrestricted profiles', () => {
  for (const grant of [
    validGrant({ cookie: 'secret' }),
    validGrant({ network_profile: 'direct_network' }),
    validGrant({ container_profile: 'host_unrestricted' }),
    validGrant({ report_submission_allowed: true }),
  ]) {
    assert.equal(
      assertLabPodStart({
        grant,
        dockerAvailable: true,
        now: '2026-07-24T01:01:00.000Z',
      }).reason,
      'server_pod_grant_required',
    );
  }
});

test('response bytes are bounded and never projected as response content', () => {
  const safe = inspectPodResponse({
    chunks: [Buffer.from('Authorization: Bearer live-token\n'), Buffer.from('{"ok":true}')],
    maxResponseBytes: 1024,
    statusCode: 200,
    contentType: 'application/json',
  });
  assert.equal(safe.outcome_class, 'ok');
  assert.equal(safe.raw_content_retained, false);
  assert.equal(safe.redacted_excerpt, '');

  const sensitive = inspectPodResponse({
    chunks: [Buffer.from('{"sessionid":"live-token","email":"owned@example.test"}')],
    maxResponseBytes: 1024,
    statusCode: 200,
    contentType: 'application/json',
  });
  assert.equal(sensitive.outcome_class, 'third_party_data');
  assert.equal(sensitive.byte_length, 0);
  assert.equal(sensitive.redacted_excerpt, '');

  const discarded = inspectPodResponse({
    chunks: [Buffer.from('{"ownership":"for'), Buffer.from('eign","email":"secret@example.test"}')],
    maxResponseBytes: 1024,
    statusCode: 200,
    contentType: 'application/json',
  });
  assert.deepEqual(discarded, {
    outcome_class: 'third_party_data',
    status_code: 200,
    content_type_class: 'json',
    byte_length: 0,
    redacted_excerpt: '',
    third_party_data_discarded: true,
    discard_completed: true,
    raw_content_retained: false,
    report_submission_allowed: false,
  });

  const oversized = inspectPodResponse({
    chunks: [Buffer.alloc(9)],
    maxResponseBytes: 8,
    statusCode: 200,
    contentType: 'application/octet-stream',
  });
  assert.equal(oversized.outcome_class, 'size_ceiling');
  assert.equal(oversized.byte_length, 0);
  assert.equal(oversized.redacted_excerpt, '');
});

test('unsupported protocols are blocked', () => {
  for (const url of [
    'ws://127.0.0.1/socket',
    'wss://127.0.0.1/socket',
    'file:///tmp/value',
    'data:text/plain,value',
    'ftp://127.0.0.1/value',
  ]) {
    assert.equal(blockUnsupportedProtocol(url).blocked, true);
  }
  assert.equal(blockUnsupportedProtocol('http://127.0.0.1/api').blocked, false);
});

test('isolation detector reports availability', () => {
  assert.equal(detectIsolationAvailability({ dockerAvailable: true }).available, true);
  assert.equal(detectIsolationAvailability({ wslAvailable: true }).available, true);
  assert.equal(detectIsolationAvailability({}).available, false);
});

function validGrant(updates = {}) {
  return {
    schema_version: 'bounty-autopilot-pod-grant/v1',
    grant_id: 'pod_grant_lab',
    campaign_id: 'campaign_lab',
    pod_id: 'pod_lab',
    authorization_id: 'auth_lab',
    authorization_digest: digest('a'),
    scope_snapshot_digest: digest('b'),
    asset_id: 'asset_lab',
    asset_identity_digest: digest('c'),
    branch_id: 'branch_lab',
    plan_id: 'plan_lab',
    plan_digest: digest('d'),
    lease_id: 'lease_lab',
    lease_status: 'active',
    recipe_ref: {
      recipe_id: 'lab_two_account_authorization_differential',
      version: '1.0.0',
      definition_digest: digest('e'),
    },
    policy_mode: 'authorized_local_lab',
    network_profile: 'gateway_only_v1',
    container_profile: 'docker_readonly_v1',
    issued_at: '2026-07-24T01:00:00.000Z',
    expires_at: '2026-07-24T01:05:00.000Z',
    report_submission_allowed: false,
    ...updates,
  };
}

function digest(character) {
  return `sha256:${character.repeat(64)}`;
}
