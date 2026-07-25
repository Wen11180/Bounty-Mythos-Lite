'use strict';

const http = require('node:http');
const https = require('node:https');
const net = require('node:net');

const { authorizeDestination } = require('./autopilot-network-guard.cjs');
const { assertGatewayBoundLabPod } = require('./autopilot-pod.cjs');

const allowedMethods = new Set(['GET', 'HEAD', 'OPTIONS']);
const safeIdPattern = /^[A-Za-z][A-Za-z0-9_:-]{0,127}$/u;
const safePathPattern = /^\/(?!.*(?:^|\/)\.?(?:\/|$))[A-Za-z0-9._~!$&'()*+,;=:@/\-]*$/u;

function createAutopilotBrowserRunner({
  apiClient,
  createObservationId = () => `obs_${Date.now().toString(36)}`,
  createReceiptId = () => `receipt_${Date.now().toString(36)}`,
  executeRequest = executeBoundHttpRequest,
  resolveHost = resolveHostAddresses,
  assertPodStart,
} = {}) {
  if (
    !apiClient
    || typeof apiClient.authorize !== 'function'
    || typeof apiClient.complete !== 'function'
    || typeof apiClient.receipt !== 'function'
    || typeof apiClient.observe !== 'function'
    || typeof createObservationId !== 'function'
    || typeof createReceiptId !== 'function'
    || typeof executeRequest !== 'function'
    || typeof resolveHost !== 'function'
    || typeof assertPodStart !== 'function'
  ) {
    throw new Error('autopilot_browser_runner_config_required');
  }

  let active = null;

  async function run(input, { isCurrent = () => true } = {}) {
    if (active !== null) {
      throw new Error('autopilot_runner_busy');
    }
    const request = validateRunnerRequest(input);
    if (!isCurrent()) {
      throw new Error('autopilot_runner_cancelled');
    }
    const abortController = new AbortController();
    const task = runBoundRequest(request, abortController, isCurrent);
    active = { abortController, task };
    try {
      return await task;
    } finally {
      if (active?.task === task) {
        active = null;
      }
    }
  }

  async function runBoundRequest(request, abortController, isCurrent) {
    let gateway;
    try {
      gateway = await apiClient.authorize(request.campaignId, {
        lease_id: request.leaseId,
        reservation_id: request.reservationId,
        method: request.method,
        scheme: request.scheme,
        host: request.host,
        port: request.port,
        path: request.path,
      });
    } catch {
      await completeQuietly(request.campaignId, request.reservationId, 'awaiting_human');
      throw new Error('autopilot_gateway_unavailable');
    }

    if (gateway?.status !== 'allowed') {
      return blockedResult(gateway?.outcome_class);
    }

    let binding;
    try {
      binding = validateExecutionBinding(gateway.execution_binding);
      assertBindingMatchesRequest(binding, request);
    } catch (error) {
      await completeQuietly(request.campaignId, request.reservationId, 'no_send_failure');
      throw error;
    }
    const pod = assertPodStart({ gateway, binding });
    if (!pod || pod.ok !== true) {
      await completeQuietly(binding.campaign_id, binding.reservation_id, 'no_send_failure');
      throw new Error(
        typeof pod?.reason === 'string' ? pod.reason : 'gateway_authorization_required',
      );
    }

    if (!isCurrent() || abortController.signal.aborted) {
      await completeQuietly(binding.campaign_id, binding.reservation_id, 'no_send_failure');
      throw new Error('autopilot_runner_cancelled');
    }

    let resolvedIps;
    try {
      resolvedIps = normalizeIps(await resolveHost(binding.host));
    } catch {
      resolvedIps = [];
    }
    const destination = authorizeDestination({
      host: binding.host,
      port: binding.port,
      allowedHost: binding.host,
      allowedPort: binding.port,
      resolvedIps,
      admittedIps: binding.admitted_ips,
    });
    if (!destination.allowed || !isCurrent() || abortController.signal.aborted) {
      await completeQuietly(binding.campaign_id, binding.reservation_id, 'no_send_failure');
      const outcome = destination.reason === 'dns_rebind_or_public_ip'
        || destination.reason === 'dns_admission_mismatch'
        ? 'dns_rebind'
        : 'scope_escape';
      await observeQuietly(binding, buildObservation({
        binding,
        outcomeClass: outcome,
        observationId: createObservationId(),
      }));
      return blockedResult(outcome);
    }

    let response;
    try {
      response = await executeRequest(binding, resolvedIps[0], {
        signal: abortController.signal,
      });
    } catch {
      await completeQuietly(binding.campaign_id, binding.reservation_id, 'awaiting_human');
      await observeQuietly(binding, buildObservation({
        binding,
        outcomeClass: 'request_failed',
        observationId: createObservationId(),
      }));
      return blockedResult('request_failed');
    }

    const metadata = validateResponseMetadata(response);
    const outcome = classifyResponseOutcome(metadata, binding.max_response_bytes);
    let receiptResult;
    try {
      receiptResult = await apiClient.receipt(binding.campaign_id, {
        receipt: {
          schema_version: 'autopilot_transport_receipt_v1',
          receipt_id: requireSafeId(createReceiptId(), 'receipt_id'),
          campaign_id: binding.campaign_id,
          lease_id: binding.lease_id,
          reservation_id: binding.reservation_id,
          plan_id: binding.plan_id,
          plan_digest: binding.plan_digest,
          branch_id: binding.branch_id,
          method: binding.method,
          scheme: binding.scheme,
          host: binding.host,
          port: binding.port,
          path: binding.path,
          body_digest: null,
          status_code: metadata.statusCode,
          content_type_class: contentTypeClassFor(metadata.contentType),
          byte_length: metadata.byteLength,
          sent_at: new Date().toISOString(),
          transport: 'loopback_http_v1',
          challenge: binding.transport_challenge,
        },
      });
    } catch {
      await completeQuietly(binding.campaign_id, binding.reservation_id, 'awaiting_human');
      return blockedResult('request_failed');
    }
    await apiClient.complete(binding.campaign_id, {
      reservation_id: binding.reservation_id,
      outcome: 'completed',
    });
    await apiClient.observe(binding.campaign_id, {
      observation: buildObservation({
        binding,
        outcomeClass: outcome,
        observationId: createObservationId(),
        metadata,
        receiptDigest: receiptResult?.receipt_digest,
      }),
    });
    return completedResult(outcome, metadata);
  }

  async function completeQuietly(campaignId, reservationId, outcome) {
    try {
      await apiClient.complete(campaignId, {
        reservation_id: reservationId,
        outcome,
      });
    } catch {
      // The release gate treats a missing outcome as incomplete evidence.
    }
  }

  async function observeQuietly(binding, observation) {
    try {
      await apiClient.observe(binding.campaign_id, { observation });
    } catch {
      // The release gate treats a missing observation as incomplete evidence.
    }
  }

  async function close() {
    if (active === null) {
      return;
    }
    active.abortController.abort();
    await active.task.catch(() => undefined);
  }

  return { close, run };
}

function validateRunnerRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('autopilot_runner_request_required');
  }
  const request = {
    campaignId: requireSafeId(value.campaignId, 'campaign_id'),
    leaseId: requireSafeId(value.leaseId, 'lease_id'),
    reservationId: requireSafeId(value.reservationId, 'reservation_id'),
    method: normalizeMethod(value.method),
    scheme: normalizeScheme(value.scheme),
    host: normalizeHost(value.host),
    port: normalizePort(value.port),
    path: normalizePath(value.path),
  };
  return request;
}

function validateExecutionBinding(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('execution_binding_required');
  }
  const expectedKeys = [
    'account_alias',
    'admitted_ips',
    'branch_id',
    'campaign_id',
    'host',
    'lease_id',
    'max_duration_seconds',
    'max_response_bytes',
    'method',
    'path',
    'plan_digest',
    'plan_id',
    'policy_mode',
    'port',
    'recipe_id',
    'recipe_version',
    'reservation_id',
    'scheme',
    'transport_challenge',
  ];
  if (
    Object.keys(value).length !== expectedKeys.length
    || expectedKeys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new Error('execution_binding_invalid');
  }
  const isBrowserMapping = (
    value.recipe_id === 'lab_browser_mapping'
    && value.recipe_version === '1.0'
    && value.account_alias === null
  );
  const isOwnedAccountDifferential = (
    value.recipe_id === 'lab_two_owned_account_readonly_authz'
    && value.recipe_version === '1.0'
    && (value.account_alias === 'account_a' || value.account_alias === 'account_b')
  );
  if (!isBrowserMapping && !isOwnedAccountDifferential) {
    throw new Error('execution_recipe_not_supported');
  }
  if (value.policy_mode !== 'authorized_local_lab') {
    throw new Error('execution_policy_mode_invalid');
  }
  const admittedIps = normalizeIps(value.admitted_ips);
  if (admittedIps.length === 0) {
    throw new Error('execution_binding_invalid');
  }
  if (
    !Number.isInteger(value.max_response_bytes)
    || value.max_response_bytes < 1
    || value.max_response_bytes > 5_000_000
    || !Number.isInteger(value.max_duration_seconds)
    || value.max_duration_seconds < 1
    || value.max_duration_seconds > 86_400
  ) {
    throw new Error('execution_binding_invalid');
  }
  if (typeof value.plan_digest !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value.plan_digest)) {
    throw new Error('execution_binding_invalid');
  }
  return {
    campaign_id: requireSafeId(value.campaign_id, 'campaign_id'),
    lease_id: requireSafeId(value.lease_id, 'lease_id'),
    reservation_id: requireSafeId(value.reservation_id, 'reservation_id'),
    plan_id: requireSafeId(value.plan_id, 'plan_id'),
    plan_digest: value.plan_digest,
    branch_id: requireSafeId(value.branch_id, 'branch_id'),
    recipe_id: value.recipe_id,
    recipe_version: value.recipe_version,
    policy_mode: value.policy_mode,
    scheme: normalizeScheme(value.scheme),
    host: normalizeHost(value.host),
    port: normalizePort(value.port),
    path: normalizePath(value.path),
    method: normalizeMethod(value.method),
    account_alias: value.account_alias,
    max_response_bytes: value.max_response_bytes,
    max_duration_seconds: value.max_duration_seconds,
    admitted_ips: admittedIps,
    transport_challenge: validateTransportChallenge(value.transport_challenge),
  };
}

function assertBindingMatchesRequest(binding, request) {
  const exact = [
    ['campaign_id', binding.campaign_id, request.campaignId],
    ['lease_id', binding.lease_id, request.leaseId],
    ['reservation_id', binding.reservation_id, request.reservationId],
    ['method', binding.method, request.method],
    ['scheme', binding.scheme, request.scheme],
    ['host', binding.host, request.host],
    ['port', binding.port, request.port],
    ['path', binding.path, request.path],
  ];
  if (exact.some(([, actual, expected]) => actual !== expected)) {
    throw new Error('execution_binding_mismatch');
  }
}

function buildObservation({ binding, outcomeClass, observationId, metadata = null, receiptDigest = null }) {
  const thirdPartyDiscarded = outcomeClass === 'third_party_data';
  const statusClass = metadata ? statusClassFor(metadata.statusCode) : 'unknown';
  const contentTypeClass = metadata ? contentTypeClassFor(metadata.contentType) : 'unknown';
  return {
    observation_id: requireSafeId(observationId, 'observation_id'),
    branch_id: binding.branch_id,
    plan_digest: binding.plan_digest,
    lease_id: binding.lease_id,
    reservation_id: binding.reservation_id,
    receipt_digest: receiptDigest,
    grade: 'L1_hint',
    outcome_class: outcomeClass,
    summary: thirdPartyDiscarded
      ? 'third_party_data_discarded'
      : `metadata_only_response:${statusClass}:${contentTypeClass}`,
    evidence_refs: thirdPartyDiscarded ? [] : ['metadata_only_response'],
    status_class: statusClass,
    content_type_class: contentTypeClass,
    byte_length: thirdPartyDiscarded ? 0 : (metadata?.byteLength ?? 0),
    third_party_data_discarded: thirdPartyDiscarded,
  };
}

function validateTransportChallenge(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/u.test(value)) {
    throw new Error('transport_challenge_invalid');
  }
  return value;
}

function completedResult(outcomeClass, metadata) {
  return {
    status: 'completed',
    outcome_class: outcomeClass,
    status_class: statusClassFor(metadata.statusCode),
    content_type_class: contentTypeClassFor(metadata.contentType),
    byte_length: outcomeClass === 'third_party_data' ? 0 : metadata.byteLength,
    third_party_data_discarded: outcomeClass === 'third_party_data',
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
  };
}

function blockedResult(outcomeClass) {
  return {
    status: 'blocked',
    outcome_class: safeOutcomeClass(outcomeClass),
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
  };
}

function safeOutcomeClass(value) {
  const allowed = new Set([
    'dns_rebind',
    'emergency_stopped',
    'lease_inactive',
    'off_scope_redirect',
    'rate_limit',
    'request_failed',
    'scope_escape',
    'size_ceiling',
    'stale_admission',
    'third_party_data',
    'waf_captcha',
  ]);
  return allowed.has(value) ? value : 'scope_escape';
}

function validateResponseMetadata(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('response_metadata_invalid');
  }
  if (
    !Number.isInteger(value.statusCode)
    || value.statusCode < 100
    || value.statusCode > 599
    || !Number.isInteger(value.byteLength)
    || value.byteLength < 0
    || value.byteLength > 5_000_001
  ) {
    throw new Error('response_metadata_invalid');
  }
  return {
    statusCode: value.statusCode,
    contentType: typeof value.contentType === 'string' ? value.contentType : '',
    byteLength: value.byteLength,
    isRedirect: value.isRedirect === true,
    wafDetected: value.wafDetected === true,
    thirdPartyDetected: value.thirdPartyDetected === true,
  };
}

function classifyResponseOutcome(metadata, maxResponseBytes) {
  if (metadata.byteLength > maxResponseBytes) return 'size_ceiling';
  if (metadata.isRedirect || (metadata.statusCode >= 300 && metadata.statusCode < 400)) {
    return 'off_scope_redirect';
  }
  if (metadata.thirdPartyDetected) return 'third_party_data';
  if (metadata.statusCode === 429) return 'rate_limit';
  if (metadata.wafDetected) return 'waf_captcha';
  if (metadata.statusCode === 401) return 'session_expired';
  return 'ok';
}

function executeBoundHttpRequest(binding, resolvedIp, { signal, sessionCookie = null } = {}) {
  const canonicalIp = normalizeIps([resolvedIp]);
  if (canonicalIp.length !== 1 || !binding.admitted_ips.includes(canonicalIp[0])) {
    return Promise.reject(new Error('bound_destination_ip_invalid'));
  }
  if (
    sessionCookie !== null
    && (typeof sessionCookie !== 'string'
      || sessionCookie.length === 0
      || sessionCookie.length > 8_192
      || /[\r\n]/u.test(sessionCookie))
  ) {
    return Promise.reject(new Error('main_session_material_invalid'));
  }
  const transport = binding.scheme === 'https' ? https : http;
  const family = net.isIP(canonicalIp[0]);
  const timeoutMs = Math.min(binding.max_duration_seconds * 1_000, 60_000);
  const headers = { accept: 'application/json, text/plain, text/html;q=0.1' };
  if (sessionCookie !== null) {
    headers.cookie = sessionCookie;
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let timeout = null;
    const settle = (error, result) => {
      if (settled) return;
      settled = true;
      if (timeout !== null) clearTimeout(timeout);
      if (error) reject(error);
      else resolve(result);
    };
    const request = transport.request({
      protocol: `${binding.scheme}:`,
      hostname: binding.host,
      port: binding.port,
      path: binding.path,
      method: binding.method,
      agent: false,
      headers,
      lookup: (_hostname, _options, callback) => callback(null, canonicalIp[0], family),
      rejectUnauthorized: true,
      signal,
    }, (response) => {
      const statusCode = Number(response.statusCode || 0);
      const contentType = typeof response.headers['content-type'] === 'string'
        ? response.headers['content-type']
        : '';
      const metadata = {
        statusCode,
        contentType,
        byteLength: 0,
        isRedirect: statusCode >= 300 && statusCode < 400,
        wafDetected: Boolean(response.headers['cf-mitigated'] || response.headers['x-waf']),
        thirdPartyDetected: response.headers['x-mythos-data-classification'] === 'third_party'
          || response.headers['x-mythos-third-party-data'] === 'true',
      };
      const declaredLength = Number(response.headers['content-length']);
      if (Number.isSafeInteger(declaredLength) && declaredLength > binding.max_response_bytes) {
        metadata.byteLength = binding.max_response_bytes + 1;
        response.destroy();
        settle(null, metadata);
        return;
      }
      response.on('data', (chunk) => {
        metadata.byteLength += Buffer.byteLength(chunk);
        if (metadata.byteLength > binding.max_response_bytes) {
          response.destroy();
          settle(null, metadata);
        }
      });
      response.once('end', () => settle(null, metadata));
      response.once('error', (error) => settle(error));
      response.resume();
    });
    timeout = setTimeout(() => request.destroy(new Error('request_duration_exhausted')), timeoutMs);
    request.once('error', (error) => settle(error));
    request.on('socket', (socket) => {
      socket.once('connect', () => {
        const remote = socket.remoteAddress;
        if (typeof remote === 'string' && normalizeIps([remote])[0] !== canonicalIp[0]) {
          request.destroy(new Error('bound_destination_ip_invalid'));
        }
      });
    });
    request.end();
  });
}

async function resolveHostAddresses(host) {
  if (net.isIP(host)) return [host];
  const { lookup } = require('node:dns').promises;
  const entries = await lookup(host, { all: true, verbatim: true });
  return entries.map((entry) => entry.address);
}

function normalizeIps(values) {
  if (!Array.isArray(values)) return [];
  const normalized = [];
  for (const value of values) {
    if (typeof value !== 'string' || net.isIP(value) === 0) return [];
    const canonical = value.toLowerCase();
    if (!normalized.includes(canonical)) normalized.push(canonical);
  }
  return normalized.sort();
}

function normalizeMethod(value) {
  const method = typeof value === 'string' ? value.toUpperCase() : '';
  if (!allowedMethods.has(method)) throw new Error('autopilot_method_not_supported');
  return method;
}

function normalizeScheme(value) {
  if (value !== 'http' && value !== 'https') throw new Error('autopilot_scheme_not_supported');
  return value;
}

function normalizeHost(value) {
  if (typeof value !== 'string') throw new Error('autopilot_host_invalid');
  const host = value.trim().toLowerCase().replace(/^\[|\]$/gu, '').replace(/\.$/u, '');
  if (!host || host.includes('/') || host.includes('\\') || host.includes('@') || /\s/u.test(host)) {
    throw new Error('autopilot_host_invalid');
  }
  return host;
}

function normalizePort(value) {
  if (!Number.isInteger(value) || value < 1 || value > 65_535) {
    throw new Error('autopilot_port_invalid');
  }
  return value;
}

function normalizePath(value) {
  if (typeof value !== 'string' || !safePathPattern.test(value) || value.includes('%')) {
    throw new Error('autopilot_path_invalid');
  }
  return value;
}

function requireSafeId(value, name) {
  if (typeof value !== 'string' || !safeIdPattern.test(value)) {
    throw new Error(`autopilot_${name}_required`);
  }
  return value;
}

function statusClassFor(statusCode) {
  return Number.isInteger(statusCode) && statusCode >= 100 && statusCode <= 599
    ? `${Math.floor(statusCode / 100)}xx`
    : 'unknown';
}

function contentTypeClassFor(contentType) {
  const value = String(contentType || '').toLowerCase();
  if (value.includes('json')) return 'json';
  if (value.includes('html')) return 'html';
  if (value.includes('text')) return 'text';
  return value ? 'other' : 'unknown';
}

module.exports = {
  assertBindingMatchesRequest,
  classifyResponseOutcome,
  contentTypeClassFor,
  createAutopilotBrowserRunner,
  executeBoundHttpRequest,
  normalizeIps,
  resolveHostAddresses,
  statusClassFor,
  validateExecutionBinding,
  validateResponseMetadata,
  validateRunnerRequest,
};
