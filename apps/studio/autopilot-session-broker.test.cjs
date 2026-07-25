'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSessionBroker } = require('./autopilot-session-broker.cjs');

test('Main-owned opaque handles bind materialization to the exact server execution binding', async () => {
  const broker = createSessionBroker();
  const handle = broker.issueBoundHandle({
    campaignId: 'c1',
    leaseId: 'lease_1',
    planDigest: `sha256:${'a'.repeat(64)}`,
    accountAlias: 'account_a',
    podId: 'pod_1',
    materialize: () => 'session=owned-account-a',
  });
  assert.equal(handle.revoked, false);
  assert.equal(Object.prototype.hasOwnProperty.call(handle, 'password'), false);
  assert.doesNotMatch(JSON.stringify(handle), /session=|owned-account/i);

  const otherCampaignHandle = broker.issueBoundHandle({
    campaignId: 'c2',
    leaseId: 'lease_2',
    planDigest: `sha256:${'b'.repeat(64)}`,
    accountAlias: 'account_b',
    podId: 'pod_2',
    materialize: () => 'session=owned-account-b',
  });

  const observed = await broker.withBoundSession(
    handle.handleId,
    {
      campaign_id: 'c1',
      lease_id: 'lease_1',
      plan_digest: `sha256:${'a'.repeat(64)}`,
      account_alias: 'account_a',
    },
    async (sessionMaterial) => sessionMaterial.length,
  );
  assert.equal(observed, 'session=owned-account-a'.length);
  await assert.rejects(
    broker.withBoundSession(
      handle.handleId,
      {
        campaign_id: 'c1',
        lease_id: 'lease_1',
        plan_digest: `sha256:${'a'.repeat(64)}`,
        account_alias: 'account_b',
      },
      async () => undefined,
    ),
    /session_binding_mismatch/,
  );
  assert.equal(broker.revokeCampaign('c1'), 1);
  const proj = broker.getProjection(handle.handleId);
  assert.equal(proj.revoked, true);
  assert.equal(broker.getProjection(otherCampaignHandle.handleId).revoked, false);
  await assert.rejects(
    broker.withBoundSession(handle.handleId, {}, async () => undefined),
    /session_handle_inactive/,
  );
});
