'use strict';

/** Fail-closed local-lab pod contract. The renderer supplies IDs only; the
 * complete grant must come from the local control-plane API. */

const grantKeys = [
  'schema_version',
  'grant_id',
  'campaign_id',
  'pod_id',
  'authorization_id',
  'authorization_digest',
  'scope_snapshot_digest',
  'asset_id',
  'asset_identity_digest',
  'branch_id',
  'plan_id',
  'plan_digest',
  'lease_id',
  'lease_status',
  'recipe_ref',
  'policy_mode',
  'network_profile',
  'container_profile',
  'issued_at',
  'expires_at',
  'report_submission_allowed',
];
const supportedRecipes = new Set([
  'lab_browser_mapping:1.0.0',
  'lab_two_account_authorization_differential:1.0.0',
]);
const thirdPartyMarkers = [
  Buffer.from('"third_party":true'),
  Buffer.from('"ownership":"foreign"'),
  Buffer.from('"pii_foreign":true'),
  Buffer.from('x-mythos-third-party-data'),
];
const sensitiveResponseMarkers = [
  ...thirdPartyMarkers,
  Buffer.from('"authorization":'),
  Buffer.from('"cookie":'),
  Buffer.from('"email":'),
  Buffer.from('"password":'),
  Buffer.from('"session":'),
  Buffer.from('"session_id":'),
  Buffer.from('"sessionid":'),
  Buffer.from('"token":'),
  Buffer.from('set-cookie:'),
];
const emailPattern = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu;

function detectIsolationAvailability({ dockerAvailable = false, wslAvailable = false } = {}) {
  return {
    dockerAvailable: Boolean(dockerAvailable),
    wslAvailable: Boolean(wslAvailable),
    available: Boolean(dockerAvailable || wslAvailable),
  };
}

function assertLabPodStart({
  grant,
  isolationRequired = true,
  isolationAvailable = null,
  dockerAvailable = false,
  wslAvailable = false,
  now = new Date().toISOString(),
} = {}) {
  if (!isPodGrant(grant)) {
    return { ok: false, reason: 'server_pod_grant_required' };
  }
  if (grant.policy_mode !== 'authorized_local_lab') {
    return { ok: false, reason: 'policy_mode_blocks_active_execution' };
  }
  if (grant.lease_status !== 'active') {
    return { ok: false, reason: 'lease_inactive' };
  }
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) {
    return { ok: false, reason: 'current_time_required' };
  }
  if (Date.parse(grant.issued_at) > nowMs || Date.parse(grant.expires_at) <= nowMs) {
    return { ok: false, reason: 'pod_grant_expired' };
  }

  const isolation = isolationAvailable == null
    ? detectIsolationAvailability({ dockerAvailable, wslAvailable })
    : normalizeIsolation(isolationAvailable);
  const profileAvailable = grant.container_profile === 'docker_readonly_v1'
    ? isolation.dockerAvailable
    : isolation.wslAvailable;
  if (isolationRequired && (!isolation.available || !profileAvailable)) {
    return { ok: false, reason: 'isolation_unavailable', isolation };
  }
  return {
    ok: true,
    reason: 'started',
    isolation,
    grant: deepFreeze(structuredClone(grant)),
  };
}

function isPodGrant(value) {
  if (!isRecord(value) || !hasExactKeys(value, grantKeys)) return false;
  if (
    value.schema_version !== 'bounty-autopilot-pod-grant/v1'
    || ![
      value.grant_id,
      value.campaign_id,
      value.pod_id,
      value.authorization_id,
      value.asset_id,
      value.branch_id,
      value.plan_id,
      value.lease_id,
    ].every(isSafeId)
    || ![
      value.authorization_digest,
      value.scope_snapshot_digest,
      value.asset_identity_digest,
      value.plan_digest,
    ].every(isDigest)
    || !isRecipeRef(value.recipe_ref)
    || value.network_profile !== 'gateway_only_v1'
    || !['docker_readonly_v1', 'wsl_readonly_v1'].includes(value.container_profile)
    || value.report_submission_allowed !== false
    || !isBoundedGrantWindow(value.issued_at, value.expires_at)
  ) {
    return false;
  }
  return true;
}

function isRecipeRef(value) {
  return isRecord(value)
    && hasExactKeys(value, ['definition_digest', 'recipe_id', 'version'])
    && supportedRecipes.has(`${value.recipe_id}:${value.version}`)
    && isDigest(value.definition_digest);
}

function isActivePodGrant(value) {
  return isPodGrant(value) && value.lease_status === 'active';
}

function isBoundedGrantWindow(issuedAt, expiresAt) {
  const issued = Date.parse(issuedAt);
  const expires = Date.parse(expiresAt);
  return Number.isFinite(issued)
    && Number.isFinite(expires)
    && expires > issued
    && expires - issued <= 60 * 60 * 1000;
}

function blockUnsupportedProtocol(url) {
  let protocol;
  try {
    protocol = new URL(String(url)).protocol;
  } catch {
    return { blocked: true, reason: 'unsupported_protocol' };
  }
  if (protocol !== 'http:' && protocol !== 'https:') {
    return { blocked: true, reason: 'unsupported_protocol' };
  }
  return { blocked: false };
}

function inspectPodResponse({
  chunks,
  maxResponseBytes,
  statusCode = null,
  contentType = null,
} = {}) {
  if (
    !Array.isArray(chunks)
    || !Number.isSafeInteger(maxResponseBytes)
    || maxResponseBytes < 1
    || !chunks.every((chunk) => Buffer.isBuffer(chunk) || chunk instanceof Uint8Array)
  ) {
    throw new Error('bounded_response_input_required');
  }
  const retained = [];
  let length = 0;
  for (const value of chunks) {
    const chunk = Buffer.from(value);
    length += chunk.length;
    if (length > maxResponseBytes) {
      retained.length = 0;
      return responseProjection({
        outcomeClass: 'size_ceiling', statusCode, contentType, byteLength: 0,
      });
    }
    retained.push(chunk);
    const normalized = Buffer.concat(retained, length)
      .toString('utf8')
      .toLowerCase()
      .replace(/\s+/gu, '');
    if (
      sensitiveResponseMarkers.some((marker) => normalized.includes(marker.toString('utf8')))
      || emailPattern.test(Buffer.concat(retained, length).toString('utf8'))
    ) {
      retained.length = 0;
      return responseProjection({
        outcomeClass: 'third_party_data', statusCode, contentType, byteLength: 0,
      });
    }
  }
  retained.length = 0;
  return responseProjection({
    outcomeClass: 'ok', statusCode, contentType, byteLength: length,
  });
}

function responseProjection({ outcomeClass, statusCode, contentType, byteLength }) {
  const discarded = outcomeClass === 'third_party_data';
  const contentDiscarded = discarded || outcomeClass === 'size_ceiling';
  return {
    outcome_class: outcomeClass,
    status_code: Number.isInteger(statusCode) ? statusCode : null,
    content_type_class: contentTypeClass(contentType),
    byte_length: contentDiscarded ? 0 : byteLength,
    redacted_excerpt: '',
    third_party_data_discarded: discarded,
    discard_completed: discarded,
    raw_content_retained: false,
    report_submission_allowed: false,
  };
}

function contentTypeClass(value) {
  const lowered = String(value || '').toLowerCase();
  if (lowered.includes('json')) return 'json';
  if (lowered.includes('html')) return 'html';
  if (lowered.includes('text')) return 'text';
  return lowered ? 'other' : 'unknown';
}

function normalizeIsolation(value) {
  const dockerAvailable = Boolean(value && value.dockerAvailable);
  const wslAvailable = Boolean(value && value.wslAvailable);
  return {
    dockerAvailable,
    wslAvailable,
    available: dockerAvailable || wslAvailable,
  };
}

function hasExactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return keys.length === wanted.length
    && keys.every((key, index) => key === wanted[index]);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isSafeId(value) {
  return typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/u.test(value);
}

function isDigest(value) {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/u.test(value);
}

function deepFreeze(value) {
  Object.freeze(value);
  for (const nested of Object.values(value)) {
    if (nested && typeof nested === 'object' && !Object.isFrozen(nested)) deepFreeze(nested);
  }
  return value;
}

module.exports = {
  assertLabPodStart,
  blockUnsupportedProtocol,
  detectIsolationAvailability,
  isActivePodGrant,
  isPodGrant,
  inspectPodResponse,
};
