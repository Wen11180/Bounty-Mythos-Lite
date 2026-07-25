'use strict';

/**
 * Opaque session broker: injects secrets only into owned Playwright contexts.
 */

const crypto = require('crypto');

const safeIdPattern = /^[A-Za-z][A-Za-z0-9_:-]{0,127}$/u;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;

function createSessionBroker() {
  const handles = new Map();

  function issueBoundHandle({
    campaignId,
    leaseId,
    planDigest,
    accountAlias,
    podId,
    generation = 1,
    materialize,
  }) {
    requireSafeId(campaignId, 'campaign_id');
    requireSafeId(leaseId, 'lease_id');
    requireSafeId(accountAlias, 'account_alias');
    requireSafeId(podId, 'pod_id');
    if (typeof planDigest !== 'string' || !digestPattern.test(planDigest)) {
      throw new Error('session_plan_digest_required');
    }
    if (!Number.isInteger(generation) || generation < 1 || typeof materialize !== 'function') {
      throw new Error('session_binding_required');
    }
    const handleId = `hdl_${crypto.randomBytes(16).toString('hex')}`;
    const record = {
      handleId,
      campaignId,
      leaseId,
      planDigest,
      accountAlias,
      podId,
      generation,
      materialize,
      revoked: false,
    };
    handles.set(handleId, record);
    return {
      handleId,
      campaignId,
      accountAlias,
      roleLabel: 'owned',
      loginState: 'logged_in',
      generation,
      podId,
      revoked: false,
    };
  }

  function revoke(handleId) {
    const current = handles.get(handleId);
    if (!current) return null;
    current.revoked = true;
    handles.set(handleId, current);
    return { ...current, loginState: 'expired' };
  }

  function revokeAll() {
    for (const id of handles.keys()) {
      revoke(id);
    }
  }

  function revokeCampaign(campaignId) {
    requireSafeId(campaignId, 'campaign_id');
    let revokedCount = 0;
    for (const [id, record] of handles) {
      if (record.campaignId === campaignId && !record.revoked) {
        revoke(id);
        revokedCount += 1;
      }
    }
    return revokedCount;
  }

  function getProjection(handleId) {
    const current = handles.get(handleId);
    if (!current) return null;
    return {
      handleId: current.handleId,
      campaignId: current.campaignId,
      accountAlias: current.accountAlias,
      roleLabel: 'owned',
      loginState: current.revoked ? 'expired' : 'logged_in',
      generation: current.generation,
      podId: current.podId,
      revoked: current.revoked,
    };
  }

  async function withBoundSession(handleId, binding, callback) {
    const current = handles.get(handleId);
    if (!current || current.revoked) {
      throw new Error('session_handle_inactive');
    }
    if (
      !binding
      || binding.campaign_id !== current.campaignId
      || binding.lease_id !== current.leaseId
      || binding.plan_digest !== current.planDigest
      || binding.account_alias !== current.accountAlias
      || typeof callback !== 'function'
    ) {
      throw new Error('session_binding_mismatch');
    }
    const sessionMaterial = current.materialize();
    if (
      typeof sessionMaterial !== 'string'
      || sessionMaterial.length === 0
      || sessionMaterial.length > 8_192
      || /[\r\n]/u.test(sessionMaterial)
    ) {
      throw new Error('session_material_invalid');
    }
    return callback(sessionMaterial);
  }

  return {
    issueBoundHandle,
    revoke,
    revokeAll,
    revokeCampaign,
    getProjection,
    withBoundSession,
  };
}

function requireSafeId(value, name) {
  if (typeof value !== 'string' || !safeIdPattern.test(value)) {
    throw new Error(`session_${name}_required`);
  }
  return value;
}

module.exports = {
  createSessionBroker,
};
