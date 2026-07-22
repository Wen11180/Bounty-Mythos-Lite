const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
const maxResponseBytes = 64 * 1024;
const minimumIntervalMs = 60_000;
const maxCampaignsPerWake = 20;
const wakeStatuses = new Set([
  "accepted",
  "completed",
  "failed",
  "lease_held",
  "lease_lost",
  "not_due",
]);
const capabilityPattern = /^[A-Za-z0-9_-]{43,128}$/u;
const wakeStopReasons = new Set([
  "wakeup_accepted",
  "wakeup_candidate_invalid",
  "wakeup_candidate_query_failed",
  "wakeup_campaign_tick_failed",
  "wakeup_lease_held",
  "wakeup_lease_lost",
  "wakeup_not_due",
]);
const wakeSafetyFields = [
  "execution_allowed",
  "dispatch_allowed",
  "validation_allowed",
  "candidate_promotion_allowed",
  "report_submission_allowed",
];

function createLocalResearchWakeup({
  fetchImpl = globalThis.fetch,
  getBaseUrl,
  getCapability,
  setIntervalImpl = setInterval,
  clearIntervalImpl = clearInterval,
  intervalMs = minimumIntervalMs,
  timeoutMs = 5_000,
  onError = (error) => console.error("local_research_wakeup_failed", error),
} = {}) {
  if (
    typeof fetchImpl !== "function"
    || typeof getBaseUrl !== "function"
    || typeof getCapability !== "function"
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
    const capability = autonomousResearchCapability(getCapability());
    const result = await requestJson(
      `${origin}/mythos/campaigns/autonomous-wakeup`,
      "POST",
      signal,
      capability,
    );
    if (signal.aborted) {
      return [];
    }
    if (!isAutonomousWakeupResult(result)) {
      throw new Error("local_research_wakeup_response_invalid");
    }
    return result;
  }

  async function requestJson(url, method, wakeSignal, capability) {
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
          headers: {
            "X-Mythos-Autonomous-Research-Capability": capability,
          },
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

function isAutonomousWakeupResult(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const expectedKeys = [
    "status",
    "stop_reason",
    "processed_count",
    "outcome_counts",
    ...wakeSafetyFields,
  ];
  if (
    Object.keys(value).length !== expectedKeys.length
    || expectedKeys.some((key) => !(key in value))
    || !wakeStatuses.has(value.status)
    || !Number.isInteger(value.processed_count)
    || value.processed_count < 0
    || value.processed_count > maxCampaignsPerWake
    || !value.outcome_counts
    || typeof value.outcome_counts !== "object"
    || Array.isArray(value.outcome_counts)
    || wakeSafetyFields.some((field) => value[field] !== false)
  ) {
    return false;
  }
  if (!isWakeStopReason(value.status, value.stop_reason)) {
    return false;
  }
  let outcomeTotal = 0;
  for (const [status, count] of Object.entries(value.outcome_counts)) {
    if (
      !/^[a-z][a-z0-9_:-]{0,127}$/u.test(status)
      || !Number.isInteger(count)
      || count < 0
      || count > maxCampaignsPerWake
    ) {
      return false;
    }
    outcomeTotal += count;
  }
  return outcomeTotal === value.processed_count;
}

function autonomousResearchCapability(value) {
  if (typeof value !== "string" || !capabilityPattern.test(value)) {
    throw new Error("local_research_wakeup_capability_required");
  }
  return value;
}

function isWakeStopReason(status, stopReason) {
  if (status === "accepted") {
    return stopReason === "wakeup_accepted";
  }
  if (status === "completed") {
    return stopReason === null || stopReason === "wakeup_campaign_tick_failed";
  }
  if (status === "failed") {
    return wakeStopReasons.has(stopReason)
      && stopReason !== "wakeup_campaign_tick_failed"
      && stopReason !== "wakeup_lease_held"
      && stopReason !== "wakeup_lease_lost";
  }
  if (status === "not_due") {
    return stopReason === "wakeup_not_due";
  }
  return (
    (status === "lease_held" && stopReason === "wakeup_lease_held")
    || (status === "lease_lost" && stopReason === "wakeup_lease_lost")
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
