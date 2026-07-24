'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { createAutopilotBrowserRunner } = require('./autopilot-browser-runner.cjs');

test('runs exactly two sequential gateway-owned read-only intents', async () => {
  const calls = [];
  let active = 0;
  let maxActive = 0;
  const runner = createAutopilotBrowserRunner({
    async executeAuthorizedRequest(intent) {
      active += 1;
      maxActive = Math.max(maxActive, active);
      calls.push(intent);
      await Promise.resolve();
      active -= 1;
      return {
        authorization_class: intent.ordinal === 1 ? 'owner_baseline' : 'comparison',
        response_shape_digest: digestOf({ ordinal: intent.ordinal }),
        status_class: '2xx',
        third_party_data_discarded: false,
      };
    },
  });

  const result = await runner.runReadOnlyDifferential({
    current_session_generations: {
      session_alpha: 7,
      session_beta: 4,
    },
    template: validTemplate(),
  });

  assert.equal(calls.length, 2);
  assert.equal(maxActive, 1);
  assert.deepEqual(calls.map((item) => item.ordinal), [1, 2]);
  assert.deepEqual(new Set(calls.map((item) => item.object_alias)), new Set(['document_alpha']));
  assert.deepEqual(new Set(calls.map((item) => item.route_template)), new Set(['/api/documents/{object}']));
  assert.deepEqual(calls.map((item) => item.session_generation), [7, 4]);
  assert.equal(result.event, 'authorization_differential_complete');
  assert.equal(result.request_count, 2);
  assert.equal(result.report_submission_allowed, false);
});

test('rejects stale generations and template tampering before dispatch', async () => {
  let calls = 0;
  const runner = createAutopilotBrowserRunner({
    async executeAuthorizedRequest() {
      calls += 1;
      return safeOutcome();
    },
  });
  await assert.rejects(
    runner.runReadOnlyDifferential({
      current_session_generations: { session_alpha: 8, session_beta: 4 },
      template: validTemplate(),
    }),
    /stale_session_generation/,
  );

  const tampered = validTemplate();
  tampered.object_alias = 'document_other';
  await assert.rejects(
    runner.runReadOnlyDifferential({
      current_session_generations: { session_alpha: 7, session_beta: 4 },
      template: tampered,
    }),
    /template_digest_mismatch/,
  );
  assert.equal(calls, 0);
});

test('rejects raw capture fields, pagination, mutations, and unsafe outcomes', async () => {
  const runner = createAutopilotBrowserRunner({
    async executeAuthorizedRequest() {
      return { ...safeOutcome(), body: 'secret' };
    },
  });
  for (const update of [
    { raw_url: 'http://127.0.0.1/api/documents/42?token=secret' },
    { query_parameter_names: ['page'] },
    { method: 'POST' },
  ]) {
    const template = validTemplate(update);
    await assert.rejects(
      runner.runReadOnlyDifferential({
        current_session_generations: { session_alpha: 7, session_beta: 4 },
        template,
      }),
    );
  }

  await assert.rejects(
    runner.runReadOnlyDifferential({
      current_session_generations: { session_alpha: 7, session_beta: 4 },
      template: validTemplate(),
    }),
    /safe_authorized_outcome_required/,
  );
});

test('runner source has no direct networking or capture implementation', () => {
  const source = fs.readFileSync(path.join(__dirname, 'autopilot-browser-runner.cjs'), 'utf8');

  assert.doesNotMatch(source, /require\(['"](?:https?|net|playwright|child_process)['"]\)/);
  assert.doesNotMatch(source, /\bfetch\s*\(|\.screenshot\s*\(|\.content\s*\(/);
  assert.match(source, /executeAuthorizedRequest/);
});

function validTemplate(updates = {}) {
  const template = {
    schema_version: 'bounty-autopilot-readonly-differential/v1',
    template_id: 'template_document_cross_account',
    campaign_id: 'campaign_lab',
    authorization_digest: digestOf({ authority: 'lab' }),
    asset_id: 'asset_lab_api',
    recipe_ref: {
      recipe_id: 'lab_two_account_authorization_differential',
      version: '1.0.0',
      definition_digest: digestOf({ recipe: 'fixed' }),
    },
    demonstrated_workflow_digest: digestOf({ workflow: 'document_read' }),
    mapping_digest: digestOf({ mapping: 'document_read' }),
    source_session: {
      session_alias: 'session_alpha',
      account_alias: 'owned_alpha',
      role_alias: 'member',
      generation: 7,
    },
    comparison_session: {
      session_alias: 'session_beta',
      account_alias: 'owned_beta',
      role_alias: 'member',
      generation: 4,
    },
    authorized_account_aliases: ['owned_alpha', 'owned_beta'],
    object_alias: 'document_alpha',
    object_owner_account_alias: 'owned_alpha',
    ownership_proof_digest: digestOf({ ownership: 'alpha' }),
    method: 'GET',
    route_template: '/api/documents/{object}',
    query_parameter_names: [],
    max_requests: 2,
    max_concurrency: 1,
    mutation_allowed: false,
    enumeration_allowed: false,
    pagination_allowed: false,
    object_substitution_allowed: false,
    report_submission_allowed: false,
  };
  Object.assign(template, updates);
  template.template_digest = digestOf(template);
  return template;
}

function safeOutcome() {
  return {
    authorization_class: 'comparison',
    response_shape_digest: digestOf({ shape: 'safe' }),
    status_class: '2xx',
    third_party_data_discarded: false,
  };
}

function digestOf(value) {
  const copy = structuredClone(value);
  delete copy.template_digest;
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
