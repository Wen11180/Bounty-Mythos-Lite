'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');

const { createAutopilotPodManager } = require('./autopilot-pod-manager.cjs');

test('starts one utility process per pod with only the validated grant', async () => {
  const child = utilityChild();
  const calls = [];
  const manager = createAutopilotPodManager({
    utilityProcess: {
      fork(modulePath, args, options) {
        calls.push({ args, modulePath, options });
        return child;
      },
    },
    workerPath: 'autopilot-pod-worker.cjs',
  });

  const started = manager.start({ grant: validGrant() });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].args, []);
  assert.equal(calls[0].modulePath, 'autopilot-pod-worker.cjs');
  assert.deepEqual(calls[0].options.env, { MYTHOS_AUTOPILOT_POD: '1' });
  assert.equal(calls[0].options.serviceName, 'Mythos Autopilot Pod');
  assert.deepEqual(child.messages, [{ type: 'start', grant: validGrant() }]);

  child.emit('message', {
    type: 'ready',
    campaign_id: 'campaign_lab',
    pod_id: 'pod_lab',
    lease_id: 'lease_lab',
  });
  assert.deepEqual(await started, {
    campaign_id: 'campaign_lab',
    lease_id: 'lease_lab',
    pod_id: 'pod_lab',
    status: 'started',
  });
  assert.deepEqual(manager.list(), [{
    campaign_id: 'campaign_lab',
    lease_id: 'lease_lab',
    pod_id: 'pod_lab',
  }]);
});

test('pod crash and emergency stop remove the process and notify the owner', async () => {
  const child = utilityChild();
  const exits = [];
  const manager = createAutopilotPodManager({
    onPodExit: (event) => exits.push(event),
    utilityProcess: { fork: () => child },
    workerPath: 'autopilot-pod-worker.cjs',
  });

  const started = manager.start({ grant: validGrant() });
  child.emit('message', {
    type: 'ready',
    campaign_id: 'campaign_lab',
    pod_id: 'pod_lab',
    lease_id: 'lease_lab',
  });
  await started;
  assert.equal(manager.stopCampaign('campaign_lab', 'emergency_stopped'), 1);
  assert.equal(child.killed, true);
  assert.deepEqual(child.messages.at(-1), {
    type: 'stop', reason: 'emergency_stopped',
  });
  assert.deepEqual(exits, [{
    campaign_id: 'campaign_lab',
    pod_id: 'pod_lab',
    reason: 'emergency_stopped',
  }]);
  assert.deepEqual(manager.list(), []);
});

test('a worker exit before readiness fails closed', async () => {
  const child = utilityChild();
  const manager = createAutopilotPodManager({
    utilityProcess: { fork: () => child },
    workerPath: 'autopilot-pod-worker.cjs',
  });

  const started = manager.start({ grant: validGrant() });
  child.emit('exit', 1);
  await assert.rejects(started, /pod_exited_before_ready/);
  assert.deepEqual(manager.list(), []);
});

test('stopping a not-yet-ready pod rejects its pending startup', async () => {
  const child = utilityChild();
  const manager = createAutopilotPodManager({
    utilityProcess: { fork: () => child },
    workerPath: 'autopilot-pod-worker.cjs',
  });

  const started = manager.start({ grant: validGrant() });
  assert.equal(manager.stopAll('app_exit'), 1);
  await assert.rejects(started, /pod_stopped/);
});

function utilityChild() {
  const child = new EventEmitter();
  child.killed = false;
  child.messages = [];
  child.postMessage = (message) => child.messages.push(structuredClone(message));
  child.kill = () => {
    child.killed = true;
  };
  return child;
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
