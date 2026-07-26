'use strict';

const { authorizeDestination } = require('./autopilot-network-guard.cjs');
const {
  assertBindingMatchesRequest,
  classifyResponseOutcome,
  contentTypeClassFor,
  executeBoundHttpRequest,
  normalizeIps,
  resolveHostAddresses,
  statusClassFor,
  validateExecutionBinding,
  validateResponseMetadata,
} = require('./autopilot-browser-runner.cjs');

const R2_ALIASES = ['account_a', 'account_b'];
const safeIdPattern = /^[A-Za-z][A-Za-z0-9_:-]{0,127}$/u;

function createAutopilotR2Runner({
  apiClient,
  assertPodStart,
  createObservationId = () => `obs_${Date.now().toString(36)}`,
  createReceiptId = (accountAlias) => `receipt_${accountAlias}_${Date.now().toString(36)}`,
  executeRequest = executeBoundHttpRequest,
  hasAccountAlias,
  openSession,
  resolveHost = resolveHostAddresses,
  revokeSession,
  runWithSession,
} = {}) {
  if (
    !apiClient
    || typeof apiClient.authorize !== 'function'
    || typeof apiClient.complete !== 'function'
    || typeof apiClient.receipt !== 'function'
    || typeof apiClient.observe !== 'function'
    || typeof assertPodStart !== 'function'
    || typeof createObservationId !== 'function'
    || typeof createReceiptId !== 'function'
    || typeof executeRequest !== 'function'
    || typeof hasAccountAlias !== 'function'
    || typeof openSession !== 'function'
    || typeof resolveHost !== 'function'
    || typeof revokeSession !== 'function'
    || typeof runWithSession !== 'function'
  ) {
    throw new Error('autopilot_r2_runner_config_required');
  }

  let active = null;

  async function run(input, { isCurrent = () => true } = {}) {
    if (active !== null) {
      throw new Error('autopilot_r2_runner_busy');
    }
    const request = validateR2RunnerRequest(input);
    if (!isCurrent()) {
      throw new Error('autopilot_runner_cancelled');
    }
    for (const accountAlias of R2_ALIASES) {
      if (!await hasAccountAlias(accountAlias)) {
        throw new Error('r2_account_session_required');
      }
    }
    const abortController = new AbortController();
    const task = runDifferential(request, abortController, isCurrent);
    active = { abortController, campaignId: request.campaignId, task };
    try {
      return await task;
    } finally {
      if (active?.task === task) {
        active = null;
      }
    }
  }

  async function runDifferential(request, abortController, isCurrent) {
    const primary = await executeOwnedAccount(
      request,
      R2_ALIASES[0],
      request.accountAReservationId,
      abortController,
      isCurrent,
    );
    if (primary.terminal) {
      await completeQuietly(request.campaignId, request.accountBReservationId, 'no_send_failure');
      return blockedResult(primary.outcomeClass);
    }

    const comparison = await executeOwnedAccount(
      request,
      R2_ALIASES[1],
      request.accountBReservationId,
      abortController,
      isCurrent,
    );
    if (comparison.terminal) {
      return blockedResult(comparison.outcomeClass);
    }
    if (!sameR2Binding(primary.binding, comparison.binding)) {
      return blockedResult('scope_escape');
    }

    const observation = buildDifferentialObservation({
      primary,
      comparison,
      observationId: createObservationId(),
    });
    try {
      await apiClient.observe(request.campaignId, { observation });
    } catch {
      return blockedResult('request_failed');
    }
    return completedResult(primary.metadata, comparison.metadata);
  }

  async function executeOwnedAccount(request, accountAlias, reservationId, abortController, isCurrent) {
    if (!isCurrent() || abortController.signal.aborted) {
      await completeQuietly(request.campaignId, reservationId, 'no_send_failure');
      return { terminal: true, outcomeClass: 'emergency_stopped' };
    }

    let gateway;
    try {
      gateway = await apiClient.authorize(request.campaignId, {
        lease_id: request.leaseId,
        reservation_id: reservationId,
        account_alias: accountAlias,
        method: request.method,
        scheme: request.scheme,
        host: request.host,
        port: request.port,
        path: request.path,
      });
    } catch {
      await completeQuietly(request.campaignId, reservationId, 'no_send_failure');
      return { terminal: true, outcomeClass: 'request_failed' };
    }
    if (gateway?.status !== 'allowed') {
      await completeQuietly(request.campaignId, reservationId, 'no_send_failure');
      return { terminal: true, outcomeClass: gateway?.outcome_class || 'scope_escape' };
    }

    let binding;
    try {
      binding = validateExecutionBinding(gateway.execution_binding);
      assertBindingMatchesRequest(binding, {
        ...request,
        reservationId,
        accountAlias,
      });
      if (
        binding.recipe_id !== 'lab_two_owned_account_readonly_authz'
        || binding.recipe_version !== '1.0'
        || binding.account_alias !== accountAlias
      ) {
        throw new Error('execution_recipe_not_supported');
      }
    } catch {
      await completeQuietly(request.campaignId, reservationId, 'no_send_failure');
      return { terminal: true, outcomeClass: 'scope_escape' };
    }

    const pod = assertPodStart({ gateway, binding, mainSessionBound: true });
    if (!pod || pod.ok !== true) {
      await completeQuietly(request.campaignId, reservationId, 'no_send_failure');
      return { terminal: true, outcomeClass: 'scope_escape' };
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
      await completeQuietly(request.campaignId, reservationId, 'no_send_failure');
      return {
        terminal: true,
        outcomeClass: destination.reason === 'dns_rebind_or_non_loopback_ip'
          || destination.reason === 'dns_admission_mismatch'
          ? 'dns_rebind'
          : 'scope_escape',
      };
    }

    let handle = null;
    let transportStarted = false;
    let response;
    try {
      handle = await openSession(binding);
      response = await runWithSession(handle, binding, async (sessionCookie) => {
        transportStarted = true;
        return executeRequest(binding, resolvedIps[0], {
          signal: abortController.signal,
          sessionCookie,
        });
      });
    } catch {
      await completeQuietly(
        request.campaignId,
        reservationId,
        transportStarted ? 'awaiting_human' : 'no_send_failure',
      );
      return { terminal: true, outcomeClass: 'request_failed' };
    } finally {
      if (handle !== null) {
        await revokeSession(handle);
      }
    }

    let metadata;
    try {
      metadata = validateResponseMetadata(response);
    } catch {
      await completeQuietly(request.campaignId, reservationId, 'awaiting_human');
      return { terminal: true, outcomeClass: 'request_failed' };
    }
    const outcomeClass = classifyResponseOutcome(metadata, binding.max_response_bytes);
    let receiptResult;
    try {
      receiptResult = await apiClient.receipt(request.campaignId, {
        receipt: buildReceipt(binding, metadata, createReceiptId(accountAlias)),
      });
      if (typeof receiptResult?.receipt_digest !== 'string') {
        throw new Error('receipt_digest_required');
      }
      await apiClient.complete(request.campaignId, {
        reservation_id: reservationId,
        outcome: 'completed',
      });
    } catch {
      await completeQuietly(request.campaignId, reservationId, 'awaiting_human');
      return { terminal: true, outcomeClass: 'request_failed' };
    }
    return {
      terminal: outcomeClass !== 'ok',
      outcomeClass,
      binding,
      metadata,
      receiptDigest: receiptResult.receipt_digest,
    };
  }

  async function completeQuietly(campaignId, reservationId, outcome) {
    try {
      await apiClient.complete(campaignId, { reservation_id: reservationId, outcome });
    } catch {
      // A terminal ledger gap remains visible to the server release gate.
    }
  }

  async function close() {
    if (active === null) {
      return;
    }
    active.abortController.abort();
    await active.task.catch(() => undefined);
  }

  function activeCampaignId() {
    return active?.campaignId ?? null;
  }

  async function closeCampaign(campaignId) {
    const safeCampaignId = requireSafeId(campaignId, 'campaign_id');
    if (active?.campaignId !== safeCampaignId) {
      return false;
    }
    await close();
    return true;
  }

  return { activeCampaignId, close, closeCampaign, run };
}

function validateR2RunnerRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('autopilot_r2_runner_request_invalid');
  }
  const expectedKeys = [
    'accountAReservationId',
    'accountBReservationId',
    'campaignId',
    'host',
    'leaseId',
    'method',
    'path',
    'port',
    'scheme',
  ];
  if (
    Object.keys(value).length !== expectedKeys.length
    || expectedKeys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new Error('autopilot_r2_runner_request_invalid');
  }
  const request = {
    campaignId: requireSafeId(value.campaignId, 'campaign_id'),
    leaseId: requireSafeId(value.leaseId, 'lease_id'),
    accountAReservationId: requireSafeId(value.accountAReservationId, 'reservation_id'),
    accountBReservationId: requireSafeId(value.accountBReservationId, 'reservation_id'),
    method: normalizeMethod(value.method),
    scheme: normalizeScheme(value.scheme),
    host: normalizeHost(value.host),
    port: normalizePort(value.port),
    path: normalizePath(value.path),
  };
  if (request.accountAReservationId === request.accountBReservationId) {
    throw new Error('autopilot_r2_runner_request_invalid');
  }
  return request;
}

function buildReceipt(binding, metadata, receiptId) {
  return {
    schema_version: 'autopilot_transport_receipt_v1',
    receipt_id: requireSafeId(receiptId, 'receipt_id'),
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
  };
}

function buildDifferentialObservation({ primary, comparison, observationId }) {
  const statusClass = statusClassFor(primary.metadata.statusCode);
  const comparisonStatusClass = statusClassFor(comparison.metadata.statusCode);
  const contentTypeClass = contentTypeClassFor(primary.metadata.contentType);
  const comparisonContentTypeClass = contentTypeClassFor(comparison.metadata.contentType);
  const byteLength = primary.metadata.byteLength;
  const comparisonByteLength = comparison.metadata.byteLength;
  return {
    observation_id: requireSafeId(observationId, 'observation_id'),
    branch_id: primary.binding.branch_id,
    plan_digest: primary.binding.plan_digest,
    lease_id: primary.binding.lease_id,
    reservation_id: primary.binding.reservation_id,
    comparison_reservation_id: comparison.binding.reservation_id,
    receipt_digest: primary.receiptDigest,
    comparison_receipt_digest: comparison.receiptDigest,
    grade: 'L1_hint',
    outcome_class: 'ok',
    summary: 'owned_account_differential_metadata_only',
    evidence_refs: ['metadata_only_response'],
    status_class: statusClass,
    content_type_class: contentTypeClass,
    byte_length: byteLength,
    comparison_status_class: comparisonStatusClass,
    comparison_content_type_class: comparisonContentTypeClass,
    comparison_byte_length: comparisonByteLength,
    difference_labels: [
      statusClass === comparisonStatusClass ? 'status_class_same' : 'status_class_different',
      contentTypeClass === comparisonContentTypeClass
        ? 'content_type_class_same'
        : 'content_type_class_different',
      byteLength === comparisonByteLength ? 'byte_length_same' : 'byte_length_different',
    ],
    third_party_data_discarded: false,
  };
}

function sameR2Binding(primaryBinding, comparisonBinding) {
  if (!primaryBinding || !comparisonBinding) {
    return false;
  }
  return [
    'campaign_id',
    'lease_id',
    'plan_id',
    'plan_digest',
    'branch_id',
    'recipe_id',
    'recipe_version',
    'policy_mode',
    'scheme',
    'host',
    'port',
    'path',
    'method',
  ].every((field) => primaryBinding[field] === comparisonBinding[field]);
}

function blockedResult(outcomeClass) {
  return {
    status: 'blocked',
    outcome_class: safeOutcomeClass(outcomeClass),
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
  };
}

function completedResult(primaryMetadata, comparisonMetadata) {
  return {
    status: 'completed',
    outcome_class: 'ok',
    status_class: statusClassFor(primaryMetadata.statusCode),
    comparison_status_class: statusClassFor(comparisonMetadata.statusCode),
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
    'session_expired',
    'size_ceiling',
    'stale_admission',
    'third_party_data',
    'waf_captcha',
  ]);
  return allowed.has(value) ? value : 'scope_escape';
}

function requireSafeId(value, name) {
  if (typeof value !== 'string' || !safeIdPattern.test(value)) {
    throw new Error(`autopilot_${name}_required`);
  }
  return value;
}

function normalizeMethod(value) {
  const method = typeof value === 'string' ? value.toUpperCase() : '';
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    throw new Error('autopilot_method_not_supported');
  }
  return method;
}

function normalizeScheme(value) {
  if (value !== 'http' && value !== 'https') {
    throw new Error('autopilot_scheme_not_supported');
  }
  return value;
}

function normalizeHost(value) {
  if (typeof value !== 'string') {
    throw new Error('autopilot_host_invalid');
  }
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
  if (
    typeof value !== 'string'
    || !/^\/(?!.*(?:^|\/)\.?(?:\/|$))[A-Za-z0-9._~!$&'()*+,;=:@/\-]*$/u.test(value)
    || value.includes('%')
  ) {
    throw new Error('autopilot_path_invalid');
  }
  return value;
}

module.exports = {
  createAutopilotR2Runner,
  validateR2RunnerRequest,
};
