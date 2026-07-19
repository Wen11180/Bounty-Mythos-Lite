const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
const maxResponseBytes = 64 * 1024;
const minimumIntervalMs = 60_000;
const maximumCampaignsPerWake = 20;

function createLocalResearchWakeup({
  fetchImpl = globalThis.fetch,
  getBaseUrl,
  setIntervalImpl = setInterval,
  clearIntervalImpl = clearInterval,
  intervalMs = minimumIntervalMs,
  timeoutMs = 5_000,
  onError = (error) => console.error("local_research_wakeup_failed", error),
} = {}) {
  if (
    typeof fetchImpl !== "function"
    || typeof getBaseUrl !== "function"
    || typeof setIntervalImpl !== "function"
    || typeof clearIntervalImpl !== "function"
    || typeof onError !== "function"
    || !Number.isInteger(intervalMs)
    || intervalMs < minimumIntervalMs
    || !Number.isInteger(timeoutMs)
    || timeoutMs < 1
  ) {
    throw new Error("local_research_wakeup_config_required");
  }

  let activeWake = null;
  let activeWakeController = null;
  let timer = null;
  let scheduling = false;
  let campaignCursor = null;

  function wake() {
    if (activeWake) {
      return activeWake;
    }
    const controller = new AbortController();
    let wakePromise;
    activeWakeController = controller;
    wakePromise = wakeDueCampaigns(controller.signal)
      .catch((error) => {
        if (controller.signal.aborted) {
          return [];
        }
        throw error;
      })
      .finally(() => {
        if (activeWake === wakePromise) {
          activeWake = null;
          activeWakeController = null;
        }
      });
    activeWake = wakePromise;
    return wakePromise;
  }

  async function wakeDueCampaigns(signal) {
    const origin = exactLoopbackApiOrigin(getBaseUrl());
    const cursorQuery = campaignCursor === null
      ? ""
      : `?after_id=${encodeURIComponent(campaignCursor)}`;
    const campaigns = await requestJson(
      `${origin}/mythos/campaigns/autonomous-wakeup-candidates${cursorQuery}`,
      "GET",
      signal,
    );
    if (signal.aborted) {
      return [];
    }
    if (!Array.isArray(campaigns)) {
      throw new Error("local_research_campaign_list_invalid");
    }

    const results = [];
    let attemptedCampaigns = 0;
    let nextCampaignCursor = null;
    for (const campaign of campaigns) {
      if (signal.aborted) {
        return results;
      }
      if (attemptedCampaigns >= maximumCampaignsPerWake) {
        break;
      }
      if (!isCampaignCursorItem(campaign)) {
        throw new Error("local_research_campaign_list_invalid");
      }
      nextCampaignCursor = campaign.id;
      if (!isEligibleCampaign(campaign)) {
        continue;
      }
      attemptedCampaigns += 1;
      try {
        const tick = await requestJson(
          `${origin}/mythos/campaigns/${campaign.id}/autonomous-research/tick`,
          "POST",
          signal,
        );
        if (signal.aborted) {
          return results;
        }
        if (!tick || typeof tick !== "object" || Array.isArray(tick) || typeof tick.status !== "string") {
          throw new Error("local_research_tick_response_invalid");
        }
        results.push({ campaign_id: campaign.id, status: tick.status });
      } catch {
        if (signal.aborted) {
          return results;
        }
        reportError(new Error("local_research_campaign_tick_failed"));
      }
    }
    campaignCursor = campaigns.length === 0 ? null : nextCampaignCursor;
    return results;
  }

  async function requestJson(url, method, wakeSignal) {
    const controller = new AbortController();
    const abortRequest = () => controller.abort();
    const timeout = setTimeout(abortRequest, timeoutMs);
    if (wakeSignal?.aborted) {
      abortRequest();
    } else {
      wakeSignal?.addEventListener("abort", abortRequest, { once: true });
    }

    try {
      let response;
      try {
        response = await fetchImpl(url, {
          method,
          redirect: "error",
          signal: controller.signal,
        });
      } catch {
        throw new Error("local_research_wakeup_request_failed");
      }
      if (wakeSignal?.aborted) {
        throw new Error("local_research_wakeup_stopped");
      }
      if (!response?.ok) {
        throw new Error("local_research_wakeup_request_failed");
      }
      const body = await readBoundedBody(response, controller, wakeSignal);
      if (wakeSignal?.aborted) {
        throw new Error("local_research_wakeup_stopped");
      }
      try {
        return JSON.parse(body);
      } catch {
        throw new Error("local_research_wakeup_response_invalid");
      }
    } finally {
      clearTimeout(timeout);
      wakeSignal?.removeEventListener("abort", abortRequest);
    }
  }

  function reportError(error) {
    try {
      onError(error);
    } catch {
      // Error reporting must not interrupt later fail-closed campaign ticks.
    }
  }

  function scheduleWake() {
    if (scheduling) {
      void wake().catch(reportError);
    }
  }

  function start() {
    if (timer !== null) {
      return stop;
    }
    scheduling = true;
    timer = setIntervalImpl(scheduleWake, intervalMs);
    scheduleWake();
    return stop;
  }

  async function stop() {
    scheduling = false;
    if (timer !== null) {
      clearIntervalImpl(timer);
      timer = null;
    }
    const wake = activeWake;
    activeWakeController?.abort();
    if (wake) {
      await wake.catch(() => undefined);
    }
  }

  return { start, stop, wake };
}

async function readBoundedBody(response, controller, wakeSignal) {
  if (!response?.body || typeof response.body.getReader !== "function") {
    throw new Error("local_research_wakeup_response_invalid");
  }
  const reader = response.body.getReader();
  const chunks = [];
  let byteLength = 0;
  try {
    while (true) {
      let result;
      try {
        result = await reader.read();
      } catch {
        throw new Error("local_research_wakeup_request_failed");
      }
      if (wakeSignal?.aborted) {
        throw new Error("local_research_wakeup_stopped");
      }
      if (result.done) {
        break;
      }
      if (!(result.value instanceof Uint8Array)) {
        throw new Error("local_research_wakeup_response_invalid");
      }
      byteLength += result.value.byteLength;
      if (byteLength > maxResponseBytes) {
        try {
          await reader.cancel();
        } catch {
          // The fixed size failure remains authoritative if cancellation fails.
        }
        controller.abort();
        throw new Error("local_research_wakeup_response_too_large");
      }
      chunks.push(Buffer.from(result.value));
    }
    return Buffer.concat(chunks, byteLength).toString("utf8");
  } finally {
    reader.releaseLock?.();
  }
}

function isEligibleCampaign(campaign) {
  return (
    campaign
    && typeof campaign === "object"
    && !Array.isArray(campaign)
    && /^campaign_[0-9a-f]{32}$/u.test(campaign.id ?? "")
    && campaign.autonomy_level === "level_0_read_only"
    && campaign.scope_status === "in_scope"
    && campaign.status === "running"
  );
}

function isCampaignCursorItem(campaign) {
  return (
    campaign
    && typeof campaign === "object"
    && !Array.isArray(campaign)
    && /^campaign_[0-9a-f]{32}$/u.test(campaign.id ?? "")
  );
}

function exactLoopbackApiOrigin(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("exact_loopback_api_origin_required");
  }
  if (
    typeof value !== "string"
    || parsed.protocol !== "http:"
    || !loopbackHosts.has(parsed.hostname)
    || parsed.username
    || parsed.password
    || value !== parsed.origin
  ) {
    throw new Error("exact_loopback_api_origin_required");
  }
  return parsed.origin;
}

module.exports = { createLocalResearchWakeup };
