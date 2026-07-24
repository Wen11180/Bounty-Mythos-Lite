'use strict';

const { isActivePodGrant } = require('./autopilot-pod.cjs');

function createAutopilotPodWorker({
  parentPort,
  exit = process.exit,
  now = Date.now,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  if (
    !parentPort
    || typeof parentPort.on !== 'function'
    || typeof parentPort.postMessage !== 'function'
    || typeof now !== 'function'
    || typeof setTimer !== 'function'
    || typeof clearTimer !== 'function'
  ) {
    throw new Error('autopilot_pod_parent_port_required');
  }

  let grant = null;
  let expiryTimer = null;
  let stopped = false;
  const stop = () => {
    if (grant === null || stopped) return;
    stopped = true;
    clearTimer(expiryTimer);
    parentPort.postMessage({
      type: 'stopped',
      campaign_id: grant.campaign_id,
      pod_id: grant.pod_id,
      lease_id: grant.lease_id,
    });
    exit(0);
  };
  parentPort.on('message', (message) => {
    const payload = message?.data ?? message;
    if (payload?.type === 'start') {
      if (grant !== null || !isActivePodGrant(payload.grant)) {
        parentPort.postMessage({ type: 'rejected', reason: 'server_pod_grant_required' });
        return;
      }
      const expiresAt = Date.parse(payload.grant.expires_at);
      const remainingMs = expiresAt - now();
      if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
        parentPort.postMessage({ type: 'rejected', reason: 'pod_grant_expired' });
        return;
      }
      grant = structuredClone(payload.grant);
      expiryTimer = setTimer(stop, remainingMs);
      parentPort.postMessage({
        type: 'ready',
        campaign_id: grant.campaign_id,
        pod_id: grant.pod_id,
        lease_id: grant.lease_id,
      });
      return;
    }
    if (payload?.type === 'stop' && grant !== null) {
      stop();
    }
  });
}

if (process.parentPort) {
  createAutopilotPodWorker({ parentPort: process.parentPort });
}

module.exports = { createAutopilotPodWorker };
