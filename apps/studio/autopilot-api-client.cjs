'use strict';

const { createHmac } = require('node:crypto');

const ipaddr = require('ipaddr.js');

const loopbackHosts = new Set(['localhost']);
const maxResponseBytes = 64 * 1024;
const safeIdPattern = /^[A-Za-z][A-Za-z0-9_:-]{0,127}$/u;
const capabilityPattern = /^[A-Za-z0-9_-]{43,128}$/u;

function createAutopilotApiClient({
  fetchImpl = globalThis.fetch,
  getBaseUrl,
  getCapability,
  timeoutMs = 5_000,
} = {}) {
  if (
    typeof fetchImpl !== 'function'
    || typeof getBaseUrl !== 'function'
    || typeof getCapability !== 'function'
    || !Number.isInteger(timeoutMs)
    || timeoutMs < 1
  ) {
    throw new Error('autopilot_api_client_config_required');
  }

  async function post(campaignId, suffix, payload) {
    const origin = exactLoopbackApiOrigin(getBaseUrl());
    const safeCampaignId = requireSafeId(campaignId, 'campaign_id');
    const capability = requireCapability(getCapability());
    let response;
    try {
      response = await fetchImpl(
        `${origin}/mythos/campaigns/${encodeURIComponent(safeCampaignId)}/autopilot/${suffix}`,
        {
          body: JSON.stringify(payload),
          headers: {
            accept: 'application/json',
            'content-type': 'application/json',
            'X-Mythos-Autopilot-Runner-Capability': capability,
          },
          method: 'POST',
          redirect: 'error',
          signal: AbortSignal.timeout(timeoutMs),
        },
      );
    } catch {
      throw new Error('autopilot_api_request_failed');
    }
    if (!response?.ok) {
      throw new Error('autopilot_api_request_failed');
    }
    const body = await readBoundedJson(response);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw new Error('autopilot_api_response_invalid');
    }
    return body;
  }

  return {
    authorize(campaignId, payload) {
      return post(campaignId, 'gateway/authorize', payload);
    },
    complete(campaignId, payload) {
      const reservationId = requireSafeId(payload?.reservation_id, 'reservation_id');
      const outcome = payload?.outcome;
      if (!['awaiting_human', 'completed', 'no_send_failure'].includes(outcome)) {
        return Promise.reject(new Error('autopilot_completion_outcome_required'));
      }
      return post(campaignId, 'requests/complete', {
        reservation_id: reservationId,
        outcome,
      });
    },
    observe(campaignId, payload) {
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        return Promise.reject(new Error('autopilot_observation_required'));
      }
      return post(campaignId, 'observations', payload);
    },
    localStopStatus(campaignId) {
      return post(campaignId, 'emergency-stop/local-status', {});
    },
    acknowledgeLocalStop(campaignId) {
      return post(campaignId, 'emergency-stop/local-ack', {});
    },
    receipt(campaignId, payload) {
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        return Promise.reject(new Error('autopilot_transport_receipt_required'));
      }
      const receipt = normalizeTransportReceipt(payload.receipt);
      const capability = requireCapability(getCapability());
      const signature = createHmac('sha256', capability)
        .update(receiptSigningMessage(receipt), 'utf8')
        .digest('hex');
      return post(campaignId, 'requests/receipt', { receipt, signature });
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
    || !isLoopbackHost(parsed.hostname)
    || parsed.username
    || parsed.password
    || value !== parsed.origin
  ) {
    throw new Error('exact_loopback_api_origin_required');
  }
  return parsed.origin;
}

function isLoopbackHost(hostname) {
  const normalized = hostname.replace(/^\[|\]$/gu, '').toLowerCase();
  if (loopbackHosts.has(normalized)) {
    return true;
  }
  try {
    return ipaddr.process(normalized).range() === 'loopback';
  } catch {
    return false;
  }
}

function requireSafeId(value, name) {
  if (typeof value !== 'string' || !safeIdPattern.test(value)) {
    throw new Error(`autopilot_${name}_required`);
  }
  return value;
}

function requireCapability(value) {
  if (typeof value !== 'string' || !capabilityPattern.test(value)) {
    throw new Error('autopilot_runner_capability_required');
  }
  return value;
}

async function readBoundedJson(response) {
  const contentType = response?.headers?.get?.('content-type');
  if (
    typeof contentType !== 'string'
    || !/^application\/json(?:\s*;|$)/iu.test(contentType)
  ) {
    throw new Error('autopilot_api_response_invalid');
  }

  const reader = response?.body?.getReader?.();
  if (!reader) {
    throw new Error('autopilot_api_response_invalid');
  }

  const chunks = [];
  let byteLength = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!(value instanceof Uint8Array)) {
        throw new Error('autopilot_api_response_invalid');
      }
      byteLength += value.byteLength;
      if (byteLength > maxResponseBytes) {
        try {
          await reader.cancel();
        } catch {}
        throw new Error('autopilot_api_response_too_large');
      }
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    if (error?.message === 'autopilot_api_response_too_large') {
      throw error;
    }
    if (error?.message === 'autopilot_api_response_invalid') {
      throw error;
    }
    throw new Error('autopilot_api_response_invalid');
  } finally {
    reader.releaseLock?.();
  }

  try {
    return JSON.parse(Buffer.concat(chunks, byteLength).toString('utf8'));
  } catch {
    throw new Error('autopilot_api_response_invalid');
  }
}

function normalizeTransportReceipt(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('autopilot_transport_receipt_required');
  }
  const expected = [
    'schema_version', 'receipt_id', 'campaign_id', 'lease_id',
    'reservation_id', 'plan_id', 'plan_digest', 'branch_id', 'method',
    'scheme', 'host', 'port', 'path', 'body_digest', 'status_code',
    'content_type_class', 'byte_length', 'sent_at', 'transport', 'challenge',
  ];
  if (
    Object.keys(value).length !== expected.length
    || expected.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new Error('autopilot_transport_receipt_invalid');
  }
  requireSafeId(value.receipt_id, 'receipt_id');
  requireSafeId(value.campaign_id, 'campaign_id');
  requireSafeId(value.lease_id, 'lease_id');
  requireSafeId(value.reservation_id, 'reservation_id');
  requireSafeId(value.plan_id, 'plan_id');
  requireSafeId(value.branch_id, 'branch_id');
  if (
    value.schema_version !== 'autopilot_transport_receipt_v1'
    || !/^sha256:[0-9a-f]{64}$/u.test(value.plan_digest)
    || !/^[A-Z]+$/u.test(value.method)
    || (value.scheme !== 'http' && value.scheme !== 'https')
    || typeof value.host !== 'string'
    || !Number.isInteger(value.port) || value.port < 1 || value.port > 65_535
    || typeof value.path !== 'string' || !value.path.startsWith('/')
    || (value.body_digest !== null && !/^sha256:[0-9a-f]{64}$/u.test(value.body_digest))
    || !Number.isInteger(value.status_code) || value.status_code < 100 || value.status_code > 599
    || !['json', 'html', 'text', 'other', 'unknown'].includes(value.content_type_class)
    || !Number.isInteger(value.byte_length) || value.byte_length < 0 || value.byte_length > 5_000_001
    || typeof value.sent_at !== 'string' || Number.isNaN(Date.parse(value.sent_at))
    || value.transport !== 'loopback_http_v1'
    || typeof value.challenge !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/u.test(value.challenge)
  ) {
    throw new Error('autopilot_transport_receipt_invalid');
  }
  return {
    ...value,
    method: value.method.toUpperCase(),
    sent_at: new Date(value.sent_at).toISOString(),
  };
}

function receiptSigningMessage(receipt) {
  return [
    'schema_version', 'receipt_id', 'campaign_id', 'lease_id',
    'reservation_id', 'plan_id', 'plan_digest', 'branch_id', 'method',
    'scheme', 'host', 'port', 'path', 'body_digest', 'status_code',
    'content_type_class', 'byte_length', 'sent_at', 'transport', 'challenge',
  ].map((field) => String(receipt[field] ?? '')).join('\n');
}

module.exports = {
  createAutopilotApiClient,
  exactLoopbackApiOrigin,
  normalizeTransportReceipt,
  receiptSigningMessage,
};
