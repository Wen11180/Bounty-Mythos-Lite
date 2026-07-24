'use strict';

const path = require('node:path');

const { isActivePodGrant } = require('./autopilot-pod.cjs');

function createAutopilotPodManager({
  utilityProcess,
  workerPath = path.join(__dirname, 'autopilot-pod-worker.cjs'),
  onPodExit = () => {},
  readyTimeoutMs = 5_000,
} = {}) {
  if (
    !utilityProcess
    || typeof utilityProcess.fork !== 'function'
    || typeof workerPath !== 'string'
    || !workerPath
    || typeof onPodExit !== 'function'
    || !Number.isSafeInteger(readyTimeoutMs)
    || readyTimeoutMs < 100
    || readyTimeoutMs > 30_000
  ) {
    throw new Error('autopilot_pod_manager_config_required');
  }

  const pods = new Map();

  function start({ grant } = {}) {
    if (!isActivePodGrant(grant)) {
      return Promise.reject(new Error('server_pod_grant_required'));
    }
    const key = podKey(grant.campaign_id, grant.pod_id);
    const existing = pods.get(key);
    if (existing) {
      if (
        existing.grant.grant_id === grant.grant_id
        && existing.grant.lease_id === grant.lease_id
        && existing.grant.plan_digest === grant.plan_digest
      ) {
        return existing.ready;
      }
      return Promise.reject(new Error('pod_already_active'));
    }

    let child;
    try {
      child = utilityProcess.fork(workerPath, [], {
        env: { MYTHOS_AUTOPILOT_POD: '1' },
        serviceName: 'Mythos Autopilot Pod',
        stdio: 'pipe',
      });
    } catch {
      return Promise.reject(new Error('pod_process_start_failed'));
    }
    if (
      !child
      || typeof child.on !== 'function'
      || typeof child.postMessage !== 'function'
      || typeof child.kill !== 'function'
    ) {
      return Promise.reject(new Error('pod_process_start_failed'));
    }

    const safeGrant = structuredClone(grant);
    let resolveReady;
    let rejectReady;
    const record = {
      child,
      grant: safeGrant,
      ready: new Promise((resolve, reject) => {
        resolveReady = resolve;
        rejectReady = reject;
      }),
      rejectReady,
      settled: false,
      timeout: null,
    };
    const exit = (reason, { beforeReady = false } = {}) => {
      if (pods.get(key) !== record) return;
      pods.delete(key);
      clearTimeout(record.timeout);
      if (!record.settled) {
        record.settled = true;
        rejectReady(new Error(beforeReady ? 'pod_exited_before_ready' : 'pod_stopped'));
      }
      onPodExit({
        campaign_id: safeGrant.campaign_id,
        pod_id: safeGrant.pod_id,
        reason,
      });
    };
    record.timeout = setTimeout(() => {
      exit('pod_start_timeout', { beforeReady: true });
      try {
        child.kill();
      } catch {}
    }, readyTimeoutMs);
    child.on('message', (message) => {
      const payload = message?.data ?? message;
      if (payload?.type === 'rejected' && !record.settled) {
        exit('pod_start_rejected', { beforeReady: true });
        try {
          child.kill();
        } catch {}
        return;
      }
      if (
        payload?.type !== 'ready'
        || payload.campaign_id !== safeGrant.campaign_id
        || payload.pod_id !== safeGrant.pod_id
        || payload.lease_id !== safeGrant.lease_id
      ) {
        return;
      }
      if (!record.settled) {
        record.settled = true;
        clearTimeout(record.timeout);
        resolveReady({
          campaign_id: safeGrant.campaign_id,
          lease_id: safeGrant.lease_id,
          pod_id: safeGrant.pod_id,
          status: 'started',
        });
      }
    });
    child.on('exit', () => exit('pod_exited', { beforeReady: !record.settled }));
    pods.set(key, record);
    try {
      child.postMessage({ type: 'start', grant: safeGrant });
    } catch {
      exit('pod_start_failed', { beforeReady: true });
      try {
        child.kill();
      } catch {}
    }
    return record.ready;
  }

  function stopCampaign(campaignId, reason = 'operator_stop') {
    return stopWhere((record) => record.grant.campaign_id === campaignId, reason);
  }

  function stopAll(reason = 'app_exit') {
    return stopWhere(() => true, reason);
  }

  function stopWhere(matches, reason) {
    const safeReason = safeStopReason(reason);
    let stopped = 0;
    for (const [key, record] of pods) {
      if (!matches(record)) continue;
      pods.delete(key);
      clearTimeout(record.timeout);
      if (!record.settled) {
        record.settled = true;
        record.rejectReady(new Error('pod_stopped'));
      }
      try {
        record.child.postMessage({ type: 'stop', reason: safeReason });
      } catch {}
      try {
        record.child.kill();
      } catch {}
      onPodExit({
        campaign_id: record.grant.campaign_id,
        pod_id: record.grant.pod_id,
        reason: safeReason,
      });
      stopped += 1;
    }
    return stopped;
  }

  function list() {
    return [...pods.values()].map((record) => ({
      campaign_id: record.grant.campaign_id,
      lease_id: record.grant.lease_id,
      pod_id: record.grant.pod_id,
    }));
  }

  return { list, start, stopAll, stopCampaign };
}

function podKey(campaignId, podId) {
  return `${campaignId}:${podId}`;
}

function safeStopReason(value) {
  return typeof value === 'string' && /^[a-z_]{1,64}$/u.test(value)
    ? value
    : 'operator_stop';
}

module.exports = { createAutopilotPodManager };
