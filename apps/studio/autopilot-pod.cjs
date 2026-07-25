'use strict';

/**
 * Lab research pod boundary (fail-closed).
 * Active network begins only after the local Gateway returns a bound allowance.
 * Renderer input never supplies execution authority.
 */

function detectIsolationAvailability({
  dockerAvailable = false,
  utilityProcessAvailable = false,
  wslAvailable = false,
} = {}) {
  return {
    dockerAvailable: Boolean(dockerAvailable),
    utilityProcessAvailable: Boolean(utilityProcessAvailable),
    wslAvailable: Boolean(wslAvailable),
    available: Boolean(dockerAvailable || utilityProcessAvailable || wslAvailable),
  };
}

function assertGatewayBoundLabPod({
  gatewayStatus,
  policyMode,
  workerIsolated,
  mainSessionBound = false,
}) {
  if (gatewayStatus !== 'allowed') {
    return { ok: false, reason: 'gateway_authorization_required' };
  }
  if (policyMode !== 'authorized_local_lab') {
    return { ok: false, reason: 'policy_mode_blocks_active_execution' };
  }
  if (workerIsolated !== true && mainSessionBound !== true) {
    return { ok: false, reason: 'worker_isolation_required' };
  }
  return { ok: true, reason: 'started' };
}

function blockUnsupportedProtocol(url) {
  const lower = String(url || '').toLowerCase();
  if (
    lower.startsWith('ws:') ||
    lower.startsWith('wss:') ||
    lower.startsWith('file:') ||
    lower.startsWith('data:')
  ) {
    return { blocked: true, reason: 'unsupported_protocol' };
  }
  return { blocked: false };
}

module.exports = {
  assertGatewayBoundLabPod,
  blockUnsupportedProtocol,
  detectIsolationAvailability,
};
