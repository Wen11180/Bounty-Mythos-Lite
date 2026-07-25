'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  assertGatewayBoundLabPod,
  blockUnsupportedProtocol,
  detectIsolationAvailability,
} = require('./autopilot-pod.cjs');

test('pod starts only from an allowed Gateway binding inside an isolated worker', () => {
  assert.equal(
    assertGatewayBoundLabPod({
      gatewayStatus: 'blocked',
      policyMode: 'public',
      workerIsolated: true,
    }).ok,
    false,
  );
  assert.equal(
    assertGatewayBoundLabPod({
      gatewayStatus: 'allowed',
      policyMode: 'authorized_local_lab',
      workerIsolated: false,
    }).reason,
    'worker_isolation_required',
  );
  assert.equal(
    assertGatewayBoundLabPod({
      gatewayStatus: 'allowed',
      policyMode: 'research_passive_only',
      workerIsolated: true,
    }).reason,
    'policy_mode_blocks_active_execution',
  );
  const started = assertGatewayBoundLabPod({
    gatewayStatus: 'allowed',
    policyMode: 'authorized_local_lab',
    workerIsolated: true,
  });
  assert.equal(started.ok, true);
  assert.equal(started.reason, 'started');
});

test('unsupported protocols are blocked', () => {
  assert.equal(blockUnsupportedProtocol('ws://127.0.0.1/socket').blocked, true);
  assert.equal(blockUnsupportedProtocol('http://127.0.0.1/api').blocked, false);
});

test('isolation detector reports availability', () => {
  assert.equal(detectIsolationAvailability({ dockerAvailable: true }).available, true);
  assert.equal(detectIsolationAvailability({ utilityProcessAvailable: true }).available, true);
  assert.equal(detectIsolationAvailability({}).available, false);
});
