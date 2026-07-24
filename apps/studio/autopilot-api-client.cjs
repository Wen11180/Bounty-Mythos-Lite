'use strict';

const loopbackHosts = new Set(['127.0.0.1', 'localhost', '[::1]']);
const maxResponseBytes = 32 * 1024;
const safeIdPattern = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/u;

function createAutopilotApiClient({
  fetchImpl = globalThis.fetch,
  getBaseUrl,
  timeoutMs = 5_000,
} = {}) {
  if (
    typeof fetchImpl !== 'function'
    || typeof getBaseUrl !== 'function'
    || !Number.isSafeInteger(timeoutMs)
    || timeoutMs < 1
    || timeoutMs > 10_000
  ) {
    throw new Error('autopilot_api_client_config_required');
  }

  return {
    async issuePodGrant({ campaignId, podId, leaseId } = {}) {
      for (const value of [campaignId, podId, leaseId]) {
        if (typeof value !== 'string' || !safeIdPattern.test(value)) {
          throw new Error('safe_autopilot_identifier_required');
        }
      }
      const origin = exactLoopbackApiOrigin(getBaseUrl());
      let response;
      try {
        response = await fetchImpl(
          `${origin}/mythos/campaigns/${campaignId}/autopilot/pods/grant`,
          {
            body: JSON.stringify({ lease_id: leaseId, pod_id: podId }),
            headers: { 'content-type': 'application/json' },
            method: 'POST',
            redirect: 'error',
            signal: AbortSignal.timeout(timeoutMs),
          },
        );
      } catch {
        throw new Error('autopilot_api_request_failed');
      }
      if (!response || response.ok !== true) {
        throw new Error('autopilot_api_request_failed');
      }
      const contentType = response.headers?.get?.('content-type');
      if (
        typeof contentType !== 'string'
        || !/^application\/json(?:\s*;\s*charset=[A-Za-z0-9._-]+)?$/iu.test(contentType)
      ) {
        throw new Error('autopilot_api_response_invalid');
      }
      const bytes = await readBoundedBody(response);
      try {
        const parsed = JSON.parse(bytes.toString('utf8'));
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('invalid');
        }
        return parsed;
      } catch {
        throw new Error('autopilot_api_response_invalid');
      }
    },
  };
}

function exactLoopbackApiOrigin(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('exact_loopback_api_origin_required');
  }
  if (
    typeof value !== 'string'
    || parsed.protocol !== 'http:'
    || !loopbackHosts.has(parsed.hostname)
    || parsed.username
    || parsed.password
    || value !== parsed.origin
  ) {
    throw new Error('exact_loopback_api_origin_required');
  }
  return parsed.origin;
}

async function readBoundedBody(response) {
  const chunks = [];
  let total = 0;
  const append = (value) => {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    total += chunk.length;
    if (total > maxResponseBytes) throw new Error('autopilot_api_response_too_large');
    chunks.push(chunk);
  };
  try {
    if (response.body && typeof response.body[Symbol.asyncIterator] === 'function') {
      for await (const chunk of response.body) append(chunk);
    } else if (response.body && typeof response.body.getReader === 'function') {
      const reader = response.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          append(value);
        }
      } finally {
        reader.releaseLock?.();
      }
    } else if (typeof response.text === 'function') {
      append(await response.text());
    } else {
      throw new Error('autopilot_api_response_invalid');
    }
  } catch (error) {
    if (error?.message === 'autopilot_api_response_too_large') throw error;
    throw new Error('autopilot_api_response_invalid');
  }
  return Buffer.concat(chunks, total);
}

module.exports = { createAutopilotApiClient };
