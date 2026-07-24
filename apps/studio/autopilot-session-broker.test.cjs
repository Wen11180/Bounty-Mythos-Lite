'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSessionBroker } = require('./autopilot-session-broker.cjs');

function fakeVault() {
  const versions = new Map([['account_a', 1], ['account_b', 1]]);
  return {
    hasAlias: (alias) => versions.has(alias),
    getAliasVersion: (alias) => versions.get(alias) ?? null,
    materializeForInjection: (alias) => `secret-for-${alias}`,
    bump: (alias) => versions.set(alias, (versions.get(alias) || 0) + 1),
  };
}

test('broker issues only vault-backed opaque handles and revokes by campaign', () => {
  const vault = fakeVault();
  const broker = createSessionBroker({ getVault: () => vault });
  assert.throws(
    () => broker.issueHandle({ campaignId: 'c1', accountAlias: 'missing', podId: 'pod_1' }),
    /account_alias_not_in_vault/,
  );
  const handle = broker.issueHandle({
    campaignId: 'c1',
    accountAlias: 'account_a',
    podId: 'pod_1',
  });
  assert.match(handle.handleId, /^hdl_[0-9a-f]{48}$/);
  assert.equal(Object.prototype.hasOwnProperty.call(handle, 'password'), false);
  assert.equal(broker.revokeCampaign('c1'), 1);
  assert.equal(broker.getProjection(handle.handleId).revoked, true);
});

test('broker enforces TTL, exact binding, and vault generation', () => {
  const vault = fakeVault();
  let clock = 1_000;
  const broker = createSessionBroker({ getVault: () => vault, now: () => clock, ttlMs: 100 });
  const handle = broker.issueHandle({ campaignId: 'c1', accountAlias: 'account_a', podId: 'pod_1' });
  assert.throws(
    () => broker.requireActive(handle.handleId, { campaignId: 'other' }),
    /session_binding_mismatch/,
  );
  vault.bump('account_a');
  assert.throws(() => broker.requireActive(handle.handleId), /session_generation_stale/);

  const refreshed = broker.issueHandle({ campaignId: 'c1', accountAlias: 'account_a', podId: 'pod_1' });
  clock += 101;
  assert.throws(() => broker.requireActive(refreshed.handleId), /session_handle_inactive/);
  assert.equal(broker.getProjection(refreshed.handleId).loginState, 'expired');
});

test('broker injects a secret directly and returns only an acknowledgement', () => {
  const vault = fakeVault();
  const broker = createSessionBroker({ getVault: () => vault });
  const handle = broker.issueHandle({ campaignId: 'c1', accountAlias: 'account_a', podId: 'pod_1' });
  let injected = null;
  const ack = broker.injectIntoOwnedContext({
    handleId: handle.handleId,
    campaignId: 'c1',
    accountAlias: 'account_a',
    podId: 'pod_1',
    generation: handle.generation,
    inject: (secret) => { injected = secret; },
  });
  assert.equal(injected, 'secret-for-account_a');
  assert.deepEqual(ack, { handleId: handle.handleId, generation: 1, injected: true });
  assert.equal(JSON.stringify(ack).includes('secret-for'), false);
});
