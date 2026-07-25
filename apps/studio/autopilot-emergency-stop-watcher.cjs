'use strict';

const safeIdPattern = /^[A-Za-z][A-Za-z0-9_:-]{0,127}$/u;

function createAutopilotEmergencyStopWatcher({
  apiClient,
  getActiveCampaignIds,
  now = () => Date.now(),
  pendingTtlMs = 5_000,
  pollIntervalMs = 50,
  stopLocalCampaign,
} = {}) {
  if (
    !apiClient
    || typeof apiClient.localStopStatus !== 'function'
    || typeof apiClient.acknowledgeLocalStop !== 'function'
    || typeof getActiveCampaignIds !== 'function'
    || typeof stopLocalCampaign !== 'function'
    || typeof now !== 'function'
    || !Number.isInteger(pendingTtlMs)
    || pendingTtlMs < 1
    || !Number.isInteger(pollIntervalMs)
    || pollIntervalMs < 10
  ) {
    throw new Error('autopilot_emergency_stop_watcher_config_required');
  }

  const pendingLocalStops = new Map();
  let checkInFlight = false;
  let timer = null;

  function collectCampaignIds() {
    const campaignIds = new Set();
    const timestamp = now();
    for (const [campaignId, expiresAt] of pendingLocalStops) {
      if (expiresAt <= timestamp) {
        pendingLocalStops.delete(campaignId);
      } else {
        campaignIds.add(campaignId);
      }
    }

    try {
      const activeCampaignIds = getActiveCampaignIds();
      if (activeCampaignIds && typeof activeCampaignIds[Symbol.iterator] === 'function') {
        for (const campaignId of activeCampaignIds) {
          if (typeof campaignId === 'string' && safeIdPattern.test(campaignId)) {
            campaignIds.add(campaignId);
          }
        }
      }
    } catch {
      // The next bounded poll retries after a transient renderer or runner failure.
    }
    return campaignIds;
  }

  async function check() {
    if (checkInFlight) {
      return;
    }
    checkInFlight = true;
    try {
      for (const campaignId of collectCampaignIds()) {
        try {
          const status = await apiClient.localStopStatus(campaignId);
          if (!isLocalStopStatus(status, campaignId) || status.emergency_stopped !== true) {
            continue;
          }
          await stopLocalCampaign(campaignId);
          const acknowledgement = await apiClient.acknowledgeLocalStop(campaignId);
          if (isLocalStopStatus(acknowledgement, campaignId) && acknowledgement.local_stop_confirmed) {
            pendingLocalStops.delete(campaignId);
          }
        } catch {
          // No acknowledgement is emitted until the next successful local teardown.
        }
      }
    } finally {
      checkInFlight = false;
    }
  }

  function start() {
    if (timer !== null) {
      return;
    }
    timer = setInterval(() => {
      void check();
    }, pollIntervalMs);
    void check();
  }

  async function stop() {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
    pendingLocalStops.clear();
  }

  function trackLocalStop(campaignId) {
    requireSafeCampaignId(campaignId);
    pendingLocalStops.set(campaignId, now() + pendingTtlMs);
    void check();
  }

  return { check, start, stop, trackLocalStop };
}

function isLocalStopStatus(value, campaignId) {
  return (
    value
    && typeof value === 'object'
    && !Array.isArray(value)
    && value.campaign_id === campaignId
    && typeof value.emergency_stopped === 'boolean'
    && typeof value.local_stop_confirmed === 'boolean'
  );
}

function requireSafeCampaignId(value) {
  if (typeof value !== 'string' || !safeIdPattern.test(value)) {
    throw new Error('autopilot_campaign_id_required');
  }
  return value;
}

module.exports = {
  createAutopilotEmergencyStopWatcher,
};
