'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { createAutopilotPodWorker } = require('./autopilot-pod-worker.cjs');

test('worker acknowledges only IDs from a validated pod grant and stops cleanly', () => {
  const parentPort = messagePort();
  const exits = [];
  createAutopilotPodWorker({
    parentPort,
    exit: (code) => exits.push(code),
    now: () => Date.parse('2026-07-24T01:01:00.000Z'),
    setTimer: () => null,
  });

  parentPort.emit('message', { data: { type: 'start', grant: validGrant() } });
  assert.deepEqual(parentPort.messages, [{
    type: 'ready',
    campaign_id: 'campaign_lab',
    pod_id: 'pod_lab',
    lease_id: 'lease_lab',
  }]);
  parentPort.emit('message', { data: { type: 'stop', reason: 'emergency_stopped' } });
  assert.deepEqual(parentPort.messages.at(-1), {
    type: 'stopped',
    campaign_id: 'campaign_lab',
    pod_id: 'pod_lab',
    lease_id: 'lease_lab',
  });
  assert.deepEqual(exits, [0]);
});

test('worker tears down when its grant expires', () => {
  const parentPort = messagePort();
  const exits = [];
  let onExpiry = null;
  createAutopilotPodWorker({
    parentPort,
    exit: (code) => exits.push(code),
    now: () => Date.parse('2026-07-24T01:01:00.000Z'),
    setTimer: (callback, delay) => {
      assert.equal(delay, 4 * 60 * 1000);
      onExpiry = callback;
      return 'expiry-timer';
    },
    clearTimer: (timer) => assert.equal(timer, 'expiry-timer'),
  });

  parentPort.emit('message', { data: { type: 'start', grant: validGrant() } });
  assert.equal(typeof onExpiry, 'function');
  onExpiry();
  assert.deepEqual(parentPort.messages.at(-1), {
    type: 'stopped',
    campaign_id: 'campaign_lab',
    pod_id: 'pod_lab',
    lease_id: 'lease_lab',
  });
  assert.deepEqual(exits, [0]);
});

test('worker rejects malformed grants and contains no network sender', () => {
  const parentPort = messagePort();
  createAutopilotPodWorker({
    parentPort,
    exit: () => {},
    now: () => Date.parse('2026-07-24T01:01:00.000Z'),
    setTimer: () => null,
  });

  parentPort.emit('message', {
    data: { type: 'start', grant: { ...validGrant(), raw_secret: 'must-not-pass' } },
  });
  assert.deepEqual(parentPort.messages, [{
    type: 'rejected', reason: 'server_pod_grant_required',
  }]);

  const source = fs.readFileSync(path.join(__dirname, 'autopilot-pod-worker.cjs'), 'utf8');
  assert.doesNotMatch(source, /require\(['"](?:https?|net|playwright|child_process)['"]\)/);
  assert.doesNotMatch(source, /\bfetch\s*\(/);
});

function messagePort() {
  const port = new EventEmitter();
  port.messages = [];
  port.postMessage = (message) => port.messages.push(structuredClone(message));
  return port;
}

function validGrant() {
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
  };
}

function digest(character) {
  return `sha256:${character.repeat(64)}`;
}
