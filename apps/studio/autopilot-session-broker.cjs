'use strict';

/** Electron-main-only opaque session broker. */

const crypto = require('node:crypto');

const SAFE_ID = /^[A-Za-z][A-Za-z0-9_:-]{0,127}$/;
const SAFE_ALIAS = /^[a-z][a-z0-9_-]{0,31}$/;

function createSessionBroker({
  getVault = () => null,
  now = () => Date.now(),
  ttlMs = 15 * 60 * 1000,
} = {}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 60 * 60 * 1000) {
    throw new Error('invalid_session_ttl');
  }
  const handles = new Map();

  function requireBinding({ campaignId, accountAlias, podId }) {
    if (!SAFE_ID.test(String(campaignId || '')) || !SAFE_ID.test(String(podId || ''))) {
      throw new Error('invalid_session_binding');
    }
    if (!SAFE_ALIAS.test(String(accountAlias || ''))) {
      throw new Error('invalid_account_alias');
    }
    const vault = getVault();
    if (!vault || !vault.hasAlias(accountAlias)) {
      throw new Error('account_alias_not_in_vault');
    }
    return vault;
  }

  function expireIfNeeded(record) {
    if (!record.revoked && now() >= record.expiresAtMs) {
      record.revoked = true;
      record.revokeReason = 'expired';
    }
    return record;
  }

  function projection(record) {
    const current = expireIfNeeded(record);
    return {
      handleId: current.handleId,
      campaignId: current.campaignId,
      accountAlias: current.accountAlias,
      roleLabel: 'owned',
      loginState: current.revoked ? 'expired' : 'logged_in',
      generation: current.generation,
      podId: current.podId,
      expiresAt: new Date(current.expiresAtMs).toISOString(),
      revoked: current.revoked,
    };
  }

  function issueHandle({ campaignId, accountAlias, podId }) {
    const vault = requireBinding({ campaignId, accountAlias, podId });
    for (const record of handles.values()) {
      if (
        record.campaignId === campaignId &&
        record.accountAlias === accountAlias &&
        !expireIfNeeded(record).revoked
      ) {
        record.revoked = true;
        record.revokeReason = 'generation_replaced';
      }
    }
    const generation = (vault.getAliasVersion(accountAlias) || 0);
    if (generation < 1) throw new Error('account_generation_missing');
    const record = {
      handleId: `hdl_${crypto.randomBytes(24).toString('hex')}`,
      campaignId,
      accountAlias,
      podId,
      generation,
      expiresAtMs: now() + ttlMs,
      revoked: false,
      revokeReason: null,
    };
    handles.set(record.handleId, record);
    return projection(record);
  }

  function requireActive(handleId, expected = {}) {
    const current = handles.get(handleId);
    if (!current || expireIfNeeded(current).revoked) throw new Error('session_handle_inactive');
    for (const [key, value] of Object.entries(expected)) {
      if (value !== undefined && current[key] !== value) {
        throw new Error('session_binding_mismatch');
      }
    }
    const vault = getVault();
    if (!vault || vault.getAliasVersion(current.accountAlias) !== current.generation) {
      current.revoked = true;
      current.revokeReason = 'generation_stale';
      throw new Error('session_generation_stale');
    }
    return current;
  }

  function injectIntoOwnedContext({ handleId, campaignId, accountAlias, podId, generation, inject }) {
    if (typeof inject !== 'function') throw new Error('session_injector_required');
    const current = requireActive(handleId, { campaignId, accountAlias, podId, generation });
    const secret = getVault().materializeForInjection(current.accountAlias);
    inject(secret);
    return { handleId, generation: current.generation, injected: true };
  }

  function revoke(handleId, reason = 'revoked') {
    const current = handles.get(handleId);
    if (!current) return null;
    current.revoked = true;
    current.revokeReason = reason;
    return projection(current);
  }

  function revokeMatching(predicate, reason) {
    let revoked = 0;
    for (const current of handles.values()) {
      if (!current.revoked && predicate(current)) {
        revoke(current.handleId, reason);
        revoked += 1;
      }
    }
    return revoked;
  }

  function revokeCampaign(campaignId, reason = 'campaign_stopped') {
    return revokeMatching((record) => record.campaignId === campaignId, reason);
  }

  function revokePod(podId, reason = 'pod_closed') {
    return revokeMatching((record) => record.podId === podId, reason);
  }

  function revokeAll(reason = 'broker_closed') {
    return revokeMatching(() => true, reason);
  }

  function getProjection(handleId) {
    const current = handles.get(handleId);
    return current ? projection(current) : null;
  }

  return {
    issueHandle,
    requireActive,
    injectIntoOwnedContext,
    revoke,
    revokeCampaign,
    revokePod,
    revokeAll,
    getProjection,
  };
}

module.exports = { createSessionBroker };
