'use strict';

/**
 * Executes only a server-built, digest-bound two-owned-account read-only
 * template. Network ownership stays with the injected gateway/pod callback.
 */

const crypto = require('node:crypto');

const templateKeys = [
  'schema_version',
  'template_id',
  'campaign_id',
  'authorization_digest',
  'asset_id',
  'recipe_ref',
  'demonstrated_workflow_digest',
  'mapping_digest',
  'source_session',
  'comparison_session',
  'authorized_account_aliases',
  'object_alias',
  'object_owner_account_alias',
  'ownership_proof_digest',
  'method',
  'route_template',
  'query_parameter_names',
  'max_requests',
  'max_concurrency',
  'mutation_allowed',
  'enumeration_allowed',
  'pagination_allowed',
  'object_substitution_allowed',
  'report_submission_allowed',
  'template_digest',
];
const safeOutcomeKeys = [
  'authorization_class',
  'response_shape_digest',
  'status_class',
  'third_party_data_discarded',
];
const statusClasses = new Set(['2xx', '3xx', '4xx', '5xx', 'network_error']);
const authorizationClasses = new Set([
  'owner_baseline',
  'comparison',
  'blocked',
  'uncertain',
]);

function createAutopilotBrowserRunner({ executeAuthorizedRequest } = {}) {
  if (typeof executeAuthorizedRequest !== 'function') {
    throw new Error('authorized_request_executor_required');
  }
  let running = false;

  async function runReadOnlyDifferential(input) {
    if (
      !isRecord(input)
      || !hasExactKeys(input, ['current_session_generations', 'template'])
    ) {
      throw new Error('fixed_differential_input_required');
    }
    if (running) throw new Error('differential_already_running');
    const template = validateTemplate(input.template);
    validateCurrentGenerations(template, input.current_session_generations);
    const intents = buildRequestIntents(template);

    running = true;
    try {
      const outcomes = [];
      for (const intent of intents) {
        const outcome = validateSafeOutcome(await executeAuthorizedRequest(intent));
        outcomes.push({ ordinal: intent.ordinal, ...outcome });
      }
      return {
        event: 'authorization_differential_complete',
        template_digest: template.template_digest,
        request_count: outcomes.length,
        outcomes,
        report_submission_allowed: false,
      };
    } finally {
      running = false;
    }
  }

  return { runReadOnlyDifferential };
}

function validateTemplate(value) {
  if (!isRecord(value) || !hasExactKeys(value, templateKeys)) {
    throw new Error('fixed_readonly_template_required');
  }
  if (
    value.schema_version !== 'bounty-autopilot-readonly-differential/v1'
    || safeId(value.template_id) !== value.template_id
    || safeId(value.campaign_id) !== value.campaign_id
    || safeId(value.asset_id) !== value.asset_id
    || !isDigest(value.authorization_digest)
    || !isDigest(value.demonstrated_workflow_digest)
    || !isDigest(value.mapping_digest)
    || !isDigest(value.ownership_proof_digest)
    || !isDigest(value.template_digest)
  ) {
    throw new Error('fixed_readonly_template_required');
  }
  validateRecipeRef(value.recipe_ref);
  const source = validateSession(value.source_session);
  const comparison = validateSession(value.comparison_session);
  if (
    source.account_alias !== safeAlias(value.object_owner_account_alias)
    || source.account_alias === comparison.account_alias
    || source.session_alias === comparison.session_alias
    || !Array.isArray(value.authorized_account_aliases)
    || value.authorized_account_aliases.length !== 2
    || value.authorized_account_aliases[0] !== source.account_alias
    || value.authorized_account_aliases[1] !== comparison.account_alias
    || safeAlias(value.object_alias) !== value.object_alias
    || (value.method !== 'GET' && value.method !== 'HEAD')
    || validateRouteTemplate(value.route_template) !== value.route_template
    || !Array.isArray(value.query_parameter_names)
    || value.query_parameter_names.length !== 0
    || value.max_requests !== 2
    || value.max_concurrency !== 1
    || value.mutation_allowed !== false
    || value.enumeration_allowed !== false
    || value.pagination_allowed !== false
    || value.object_substitution_allowed !== false
    || value.report_submission_allowed !== false
  ) {
    throw new Error('fixed_readonly_template_required');
  }
  if (value.template_digest !== digestOf(value, 'template_digest')) {
    throw new Error('template_digest_mismatch');
  }
  return deepFreeze(structuredClone(value));
}

function validateRecipeRef(value) {
  if (
    !isRecord(value)
    || !hasExactKeys(value, ['definition_digest', 'recipe_id', 'version'])
    || value.recipe_id !== 'lab_two_account_authorization_differential'
    || value.version !== '1.0.0'
    || !isDigest(value.definition_digest)
  ) {
    throw new Error('registered_two_account_recipe_required');
  }
}

function validateSession(value) {
  if (
    !isRecord(value)
    || !hasExactKeys(value, ['account_alias', 'generation', 'role_alias', 'session_alias'])
    || safeAlias(value.account_alias) !== value.account_alias
    || safeAlias(value.role_alias) !== value.role_alias
    || safeAlias(value.session_alias) !== value.session_alias
    || !Number.isSafeInteger(value.generation)
    || value.generation < 1
  ) {
    throw new Error('safe_session_generation_binding_required');
  }
  return value;
}

function validateCurrentGenerations(template, value) {
  if (
    !isRecord(value)
    || !hasExactKeys(value, [
      template.source_session.session_alias,
      template.comparison_session.session_alias,
    ])
    || value[template.source_session.session_alias] !== template.source_session.generation
    || value[template.comparison_session.session_alias]
      !== template.comparison_session.generation
  ) {
    throw new Error('stale_session_generation');
  }
}

function buildRequestIntents(template) {
  return [template.source_session, template.comparison_session].map((session, index) => {
    const intent = {
      schema_version: 'bounty-autopilot-readonly-intent/v1',
      template_digest: template.template_digest,
      campaign_id: template.campaign_id,
      authorization_digest: template.authorization_digest,
      asset_id: template.asset_id,
      recipe_ref: template.recipe_ref,
      ordinal: index + 1,
      session_alias: session.session_alias,
      account_alias: session.account_alias,
      role_alias: session.role_alias,
      session_generation: session.generation,
      method: template.method,
      route_template: template.route_template,
      object_alias: template.object_alias,
      query_parameter_names: [],
      report_submission_allowed: false,
    };
    intent.request_digest = digestOf(intent, 'request_digest');
    return deepFreeze(intent);
  });
}

function validateSafeOutcome(value) {
  if (
    !isRecord(value)
    || !hasExactKeys(value, safeOutcomeKeys)
    || !authorizationClasses.has(value.authorization_class)
    || !statusClasses.has(value.status_class)
    || typeof value.third_party_data_discarded !== 'boolean'
    || (
      value.third_party_data_discarded
        ? value.response_shape_digest !== null
        : !isDigest(value.response_shape_digest)
    )
  ) {
    throw new Error('safe_authorized_outcome_required');
  }
  return { ...value };
}

function validateRouteTemplate(value) {
  if (
    typeof value !== 'string'
    || !value.startsWith('/')
    || value.startsWith('//')
    || value.includes('?')
    || value.includes('#')
    || value.includes('%')
    || value.includes('\\')
    || value.includes('://')
    || value.includes('//')
  ) {
    throw new Error('normalized_owned_object_route_required');
  }
  const segments = value.split('/').slice(1);
  if (
    segments.length < 1
    || segments.some((segment) => !segment || segment === '.' || segment === '..')
    || segments.filter((segment) => segment === '{object}').length !== 1
    || segments.some((segment) =>
      segment !== '{object}' && !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/u.test(segment))
  ) {
    throw new Error('normalized_owned_object_route_required');
  }
  return value;
}

function safeAlias(value) {
  if (
    typeof value !== 'string'
    || !/^[a-z][a-z0-9_-]{0,31}$/u.test(value)
    || /^[0-9a-f]{16,}$/iu.test(value)
  ) {
    throw new Error('safe_alias_required');
  }
  return value;
}

function safeId(value) {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9_.-]{0,127}$/u.test(value)) {
    throw new Error('safe_identifier_required');
  }
  return value;
}

function isDigest(value) {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/u.test(value);
}

function digestOf(value, excludedKey) {
  const copy = structuredClone(value);
  delete copy[excludedKey];
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(copy)).digest('hex')}`;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hasExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index]);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function deepFreeze(value) {
  Object.freeze(value);
  for (const nested of Object.values(value)) {
    if (nested && typeof nested === 'object' && !Object.isFrozen(nested)) deepFreeze(nested);
  }
  return value;
}

module.exports = { createAutopilotBrowserRunner };
