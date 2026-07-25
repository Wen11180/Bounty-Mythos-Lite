'use strict';

const path = require('node:path');

const { createAutopilotApiClient, exactLoopbackApiOrigin } = require('./autopilot-api-client.cjs');
const {
  createAutopilotBrowserRunner,
  validateRunnerRequest,
} = require('./autopilot-browser-runner.cjs');
const { assertGatewayBoundLabPod } = require('./autopilot-pod.cjs');

const CAPABILITY_PATTERN = /^[A-Za-z0-9_-]{43,128}$/u;
const SAFE_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_:-]{0,127}$/u;
const SAFE_ERROR_CODES = new Set([
  'autopilot_gateway_unavailable',
  'autopilot_runner_cancelled',
  'execution_binding_invalid',
  'execution_binding_mismatch',
  'execution_policy_mode_invalid',
  'execution_recipe_not_supported',
  'response_metadata_invalid',
  'autopilot_api_request_failed',
  'autopilot_api_response_invalid',
  'autopilot_api_response_too_large',
  'gateway_authorization_required',
  'worker_isolation_required',
]);

function createAutopilotBrowserWorkerRunner({
  utilityProcess,
  workerPath = path.join(__dirname, 'autopilot-browser-worker.cjs'),
  getBaseUrl,
  getCapability,
  pollIntervalMs = 25,
} = {}) {
  if (
    !utilityProcess
    || typeof utilityProcess.fork !== 'function'
    || typeof getBaseUrl !== 'function'
    || typeof getCapability !== 'function'
    || !Number.isInteger(pollIntervalMs)
    || pollIntervalMs < 5
  ) {
    throw new Error('autopilot_browser_worker_config_required');
  }

  let active = null;
  let permanentlyClosed = false;

  async function run(input, { isCurrent = () => true } = {}) {
    if (permanentlyClosed) {
      throw new Error('autopilot_runner_closed');
    }
    if (active !== null) {
      throw new Error('autopilot_runner_busy');
    }
    const request = validateRunnerRequest(input);
    if (!isCurrent()) {
      throw new Error('autopilot_runner_cancelled');
    }

    const apiOrigin = exactLoopbackApiOrigin(getBaseUrl());
    const capability = requireCapability(getCapability());
    const child = utilityProcess.fork(workerPath, [], {
      env: buildWorkerEnvironment(apiOrigin, capability),
      serviceName: 'Mythos Autopilot Worker',
      stdio: 'ignore',
    });

    let timer = null;
    let settled = false;
    let resolveTask;
    let rejectTask;
    const task = new Promise((resolve, reject) => {
      resolveTask = resolve;
      rejectTask = reject;
    });
    const state = {
      campaignId: request.campaignId,
      child,
      task,
      cancelSent: false,
      closeRequested: false,
    };
    active = state;

    const finish = (error, result) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
      if (error) {
        rejectTask(error);
      } else {
        resolveTask(result);
      }
    };

    const requestCancel = () => {
      if (state.cancelSent) {
        return;
      }
      state.cancelSent = true;
      try {
        child.postMessage({ type: 'cancel' });
      } catch {
        finish(new Error('autopilot_runner_cancelled'));
      }
    };

    child.on('message', (message) => {
      if (!message || typeof message !== 'object') {
        finish(new Error('autopilot_worker_message_invalid'));
        return;
      }
      if (message.type === 'result') {
        finish(null, message.result);
        return;
      }
      if (message.type === 'error') {
        finish(safeWorkerError(message.code));
      }
    });
    child.on('error', () => finish(new Error('autopilot_worker_failed')));
    child.on('exit', (code) => {
      if (!settled) {
        finish(new Error(code === 0 ? 'autopilot_worker_no_result' : 'autopilot_worker_failed'));
      }
    });

    timer = setInterval(() => {
      if (!isCurrent() && !state.closeRequested) {
        requestCancel();
      }
    }, pollIntervalMs);

    try {
      child.postMessage({ type: 'run', request });
      return await task;
    } finally {
      if (timer !== null) {
        clearInterval(timer);
      }
      if (active === state) {
        active = null;
      }
      try {
        child.kill();
      } catch {}
    }
  }

  async function close(reason = 'operator_stop') {
    if (reason === 'app_exit' || reason === 'operator_stop' || reason === 'browser_crash') {
      permanentlyClosed = reason === 'app_exit';
    }
    const state = active;
    if (!state) {
      return;
    }
    state.closeRequested = true;
    try {
      state.child.postMessage({ type: 'cancel' });
    } catch {}
    try {
      state.child.kill();
    } catch {}
    await state.task.catch(() => undefined);
  }

  function activeCampaignId() {
    return active?.campaignId ?? null;
  }

  async function closeCampaign(campaignId) {
    const safeCampaignId = requireSafeId(campaignId, 'campaign_id');
    if (active?.campaignId !== safeCampaignId) {
      return false;
    }
    await close('operator_stop');
    return true;
  }

  return { activeCampaignId, close, closeCampaign, run };
}

function buildWorkerEnvironment(apiOrigin, capability) {
  const inherited = {};
  for (const key of [
    'ELECTRON_RUN_AS_NODE',
    'LANG',
    'NODE_PATH',
    'PATH',
    'Path',
    'SYSTEMROOT',
    'SystemRoot',
    'TEMP',
    'TMP',
    'WINDIR',
  ]) {
    if (typeof process.env[key] === 'string') {
      inherited[key] = process.env[key];
    }
  }
  return {
    ...inherited,
    AUTOPILOT_API_BASE_URL: apiOrigin,
    AUTOPILOT_RUNNER_CAPABILITY: capability,
  };
}

function requireCapability(value) {
  if (typeof value !== 'string' || !CAPABILITY_PATTERN.test(value)) {
    throw new Error('autopilot_runner_capability_required');
  }
  return value;
}

function requireSafeId(value, name) {
  if (typeof value !== 'string' || !SAFE_ID_PATTERN.test(value)) {
    throw new Error(`autopilot_${name}_required`);
  }
  return value;
}

function safeWorkerError(code) {
  return new Error(
    typeof code === 'string' && SAFE_ERROR_CODES.has(code)
      ? code
      : 'autopilot_worker_failed',
  );
}

function startWorkerProcess(parentPort = process.parentPort) {
  if (!parentPort) {
    return;
  }
  const apiClient = createAutopilotApiClient({
    getBaseUrl: () => process.env.AUTOPILOT_API_BASE_URL,
    getCapability: () => process.env.AUTOPILOT_RUNNER_CAPABILITY,
  });
  const runner = createAutopilotBrowserRunner({
    apiClient,
    assertPodStart: ({ gateway, binding }) => assertGatewayBoundLabPod({
      gatewayStatus: gateway?.status,
      policyMode: binding.policy_mode,
      workerIsolated: true,
    }),
  });
  let running = false;

  parentPort.on('message', async (message) => {
    if (!message || typeof message !== 'object') {
      parentPort.postMessage({ type: 'error', code: 'autopilot_worker_message_invalid' });
      return;
    }
    if (message.type === 'cancel') {
      await runner.close();
      return;
    }
    if (message.type !== 'run' || running) {
      parentPort.postMessage({ type: 'error', code: 'autopilot_worker_message_invalid' });
      return;
    }
    running = true;
    try {
      const result = await runner.run(message.request);
      parentPort.postMessage({ type: 'result', result });
    } catch (error) {
      parentPort.postMessage({
        type: 'error',
        code: error instanceof Error && SAFE_ERROR_CODES.has(error.message)
          ? error.message
          : 'autopilot_worker_failed',
      });
    } finally {
      process.exitCode = 0;
    }
  });
}

if (process.parentPort) {
  startWorkerProcess(process.parentPort);
}

module.exports = {
  buildWorkerEnvironment,
  createAutopilotBrowserWorkerRunner,
  safeWorkerError,
  startWorkerProcess,
};
