'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  createAutopilotR2Runner,
  validateR2RunnerRequest,
} = require('./autopilot-r2-runner.cjs');

const PLAN_DIGEST = `sha256:${'a'.repeat(64)}`;

function request(overrides = {}) {
  return {
    campaignId: 'campaign_lab',
    leaseId: 'lease_r2',
    accountAReservationId: 'reservation_account_a',
    accountBReservationId: 'reservation_account_b',
    method: 'GET',
    scheme: 'http',
    host: '127.0.0.1',
    port: 18080,
    path: '/api/docs/1',
    ...overrides,
  };
}

function binding(accountAlias, reservationId, overrides = {}) {
  return {
    account_alias: accountAlias,
    admitted_ips: ['127.0.0.1'],
    branch_id: 'branch_r2',
    campaign_id: 'campaign_lab',
    host: '127.0.0.1',
    lease_id: 'lease_r2',
    max_duration_seconds: 30,
    max_response_bytes: 1024,
    method: 'GET',
    path: '/api/docs/1',
    plan_digest: PLAN_DIGEST,
    plan_id: 'plan_r2',
    policy_mode: 'authorized_local_lab',
    port: 18080,
    recipe_id: 'lab_two_owned_account_readonly_authz',
    recipe_version: '1.0',
    reservation_id: reservationId,
    scheme: 'http',
    transport_challenge: `${accountAlias[0]}`.repeat(32),
    ...overrides,
  };
}

function fixture({
  hasAccountAlias = () => true,
  gatewayFor = (accountAlias, reservationId) => ({
    status: 'allowed',
    execution_binding: binding(accountAlias, reservationId),
  }),
  executeRequest = async (_binding, _ip, { sessionCookie }) => ({
    statusCode: sessionCookie === 'session=account_a' ? 200 : 404,
    contentType: 'application/json',
    byteLength: sessionCookie === 'session=account_a' ? 24 : 17,
    isRedirect: false,
    wafDetected: false,
    thirdPartyDetected: false,
  }),
} = {}) {
  const calls = [];
  const runner = createAutopilotR2Runner({
    apiClient: {
      authorize: async (campaignId, payload) => {
        calls.push({ kind: 'authorize', campaignId, payload });
        return gatewayFor(payload.account_alias, payload.reservation_id);
      },
      receipt: async (campaignId, payload) => {
        calls.push({ kind: 'receipt', campaignId, payload });
        return { receipt_digest: `sha256:${payload.receipt.receipt_id.slice(-1).repeat(64)}` };
      },
      complete: async (campaignId, payload) => {
        calls.push({ kind: 'complete', campaignId, payload });
      },
      observe: async (campaignId, payload) => {
        calls.push({ kind: 'observe', campaignId, payload });
      },
    },
    assertPodStart: ({ gateway, binding: executionBinding, mainSessionBound }) => ({
      ok: gateway.status === 'allowed'
        && executionBinding.recipe_id === 'lab_two_owned_account_readonly_authz'
        && mainSessionBound === true,
    }),
    createObservationId: () => 'observation_r2',
    createReceiptId: (accountAlias) => `receipt_${accountAlias.slice(-1)}`,
    executeRequest: async (executionBinding, ip, options) => {
      calls.push({
        kind: 'target',
        accountAlias: executionBinding.account_alias,
        ip,
        options,
      });
      return executeRequest(executionBinding, ip, options);
    },
    hasAccountAlias: (accountAlias) => {
      calls.push({ kind: 'has_account', accountAlias });
      return hasAccountAlias(accountAlias);
    },
    openSession: (executionBinding) => {
      calls.push({ kind: 'open_session', accountAlias: executionBinding.account_alias });
      return { handleId: `handle_${executionBinding.account_alias}` };
    },
    resolveHost: async () => ['127.0.0.1'],
    revokeSession: (handle) => {
      calls.push({ kind: 'revoke_session', handle });
    },
    runWithSession: async (handle, executionBinding, callback) => {
      calls.push({ kind: 'run_session', handle, accountAlias: executionBinding.account_alias });
      return callback(`session=${executionBinding.account_alias}`);
    },
  });
  return { calls, runner };
}

test('R2 runner executes exactly two owned accounts sequentially and emits one metadata-only differential', async () => {
  const { calls, runner } = fixture();

  const result = await runner.run(request());

  assert.deepEqual(
    calls.filter((call) => call.kind === 'authorize').map((call) => call.payload.account_alias),
    ['account_a', 'account_b'],
  );
  assert.deepEqual(
    calls.filter((call) => call.kind === 'target').map((call) => call.accountAlias),
    ['account_a', 'account_b'],
  );
  assert.deepEqual(
    calls.filter((call) => call.kind === 'target').map((call) => call.options.sessionCookie),
    ['session=account_a', 'session=account_b'],
  );
  assert.deepEqual(
    calls.filter((call) => call.kind === 'receipt').map((call) => call.payload.receipt.content_type_class),
    ['json', 'json'],
  );
  assert.deepEqual(
    calls.filter((call) => call.kind === 'complete').map((call) => call.payload),
    [
      { reservation_id: 'reservation_account_a', outcome: 'completed' },
      { reservation_id: 'reservation_account_b', outcome: 'completed' },
    ],
  );
  assert.deepEqual(calls.at(-1), {
    kind: 'observe',
    campaignId: 'campaign_lab',
    payload: {
      observation: {
        observation_id: 'observation_r2',
        branch_id: 'branch_r2',
        plan_digest: PLAN_DIGEST,
        lease_id: 'lease_r2',
        reservation_id: 'reservation_account_a',
        comparison_reservation_id: 'reservation_account_b',
        receipt_digest: `sha256:${'a'.repeat(64)}`,
        comparison_receipt_digest: `sha256:${'b'.repeat(64)}`,
        grade: 'L1_hint',
        outcome_class: 'ok',
        summary: 'owned_account_differential_metadata_only',
        evidence_refs: ['metadata_only_response'],
        status_class: '2xx',
        content_type_class: 'json',
        byte_length: 24,
        comparison_status_class: '4xx',
        comparison_content_type_class: 'json',
        comparison_byte_length: 17,
        difference_labels: [
          'status_class_different',
          'content_type_class_same',
          'byte_length_different',
        ],
        third_party_data_discarded: false,
      },
    },
  });
  assert.equal(result.status, 'completed');
  assert.doesNotMatch(JSON.stringify(result), /session=|127\.0\.0\.1|docs/i);
});

test('R2 runner rejects an unavailable owned account before gateway authorization', async () => {
  const { calls, runner } = fixture({
    hasAccountAlias: (accountAlias) => accountAlias === 'account_a',
  });

  await assert.rejects(runner.run(request()), /r2_account_session_required/);
  assert.deepEqual(calls.map((call) => call.kind), ['has_account', 'has_account']);
});

test('R2 runner closes only the matching active campaign', async () => {
  let markTargetStarted;
  const targetStarted = new Promise((resolve) => {
    markTargetStarted = resolve;
  });
  const { calls, runner } = fixture({
    executeRequest: async (_binding, _ip, { signal }) => {
      markTargetStarted();
      await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
      throw new Error('request_aborted');
    },
  });

  const pending = runner.run(request());
  await targetStarted;
  assert.equal(runner.activeCampaignId(), 'campaign_lab');
  assert.equal(await runner.closeCampaign('campaign_other'), false);
  assert.equal(await runner.closeCampaign('campaign_lab'), true);

  const result = await pending;
  assert.equal(runner.activeCampaignId(), null);
  assert.equal(result.status, 'blocked');
  assert.equal(calls.filter((call) => call.kind === 'revoke_session').length, 1);
});

test('R2 runner rejects a Gateway binding drift before emitting a differential observation', async () => {
  const { calls, runner } = fixture({
    gatewayFor: (accountAlias, reservationId) => ({
      status: 'allowed',
      execution_binding: binding(
        accountAlias,
        reservationId,
        accountAlias === 'account_b'
          ? {
            branch_id: 'branch_other',
            plan_digest: `sha256:${'c'.repeat(64)}`,
            plan_id: 'plan_other',
          }
          : {},
      ),
    }),
  });

  const result = await runner.run(request());

  assert.deepEqual(result, {
    candidate_promotion_allowed: false,
    outcome_class: 'scope_escape',
    report_submission_allowed: false,
    status: 'blocked',
  });
  assert.equal(calls.filter((call) => call.kind === 'observe').length, 0);
});

test('R2 runner rejects renderer-provided arbitrary transport fields', () => {
  assert.throws(
    () => validateR2RunnerRequest({ ...request(), headers: { authorization: 'secret' } }),
    /autopilot_r2_runner_request_invalid/,
  );
});
