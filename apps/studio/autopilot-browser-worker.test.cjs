'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  buildWorkerEnvironment,
  createAutopilotBrowserWorkerRunner,
  safeWorkerError,
} = require('./autopilot-browser-worker.cjs');

test('worker environment contains only the bounded local control-plane inputs', () => {
  const environment = buildWorkerEnvironment(
    'http://127.0.0.1:48123',
    'A'.repeat(43),
  );
  assert.equal(environment.AUTOPILOT_API_BASE_URL, 'http://127.0.0.1:48123');
  assert.equal(environment.AUTOPILOT_RUNNER_CAPABILITY, 'A'.repeat(43));
  assert.equal(environment.AUTONOMOUS_RESEARCH_CAPABILITY, undefined);
  assert.equal(environment.OPENAI_API_KEY, undefined);
});

test('worker runner starts one utility process and kills it on close', async () => {
  const messages = [];
  let killed = false;
  const child = {
    on(event, callback) {
      if (event === 'message') this.message = callback;
      if (event === 'exit') this.exit = callback;
      if (event === 'error') this.error = callback;
    },
    postMessage(message) {
      messages.push(message);
    },
    kill() {
      killed = true;
      this.exit?.(0);
    },
  };
  const worker = createAutopilotBrowserWorkerRunner({
    utilityProcess: { fork: () => child },
    getBaseUrl: () => 'http://127.0.0.1:48123',
    getCapability: () => 'A'.repeat(43),
    pollIntervalMs: 5,
  });

  const pending = worker.run({
    campaignId: 'campaign_lab',
    leaseId: 'lease_lab',
    reservationId: 'reservation_lab',
    method: 'GET',
    scheme: 'http',
    host: '127.0.0.1',
    port: 18080,
    path: '/api',
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(messages[0].type, 'run');
  assert.equal(worker.activeCampaignId(), 'campaign_lab');
  assert.equal(await worker.closeCampaign('campaign_other'), false);
  assert.equal(await worker.closeCampaign('campaign_lab'), true);
  await pending.catch((error) => assert.match(error.message, /worker|cancelled/i));
  assert.equal(worker.activeCampaignId(), null);
  assert.equal(killed, true);
  assert.equal(messages.some((message) => message.type === 'cancel'), true);
});

test('worker errors are reduced to fixed safe identifiers', () => {
  assert.equal(safeWorkerError('execution_binding_mismatch').message, 'execution_binding_mismatch');
  assert.equal(safeWorkerError('secret_value').message, 'autopilot_worker_failed');
});
