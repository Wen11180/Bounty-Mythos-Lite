'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  createAutopilotEmergencyStopWatcher,
} = require('./autopilot-emergency-stop-watcher.cjs');

test('watcher closes the matching local context before acknowledging a server emergency stop', async () => {
  const calls = [];
  const watcher = createAutopilotEmergencyStopWatcher({
    apiClient: {
      acknowledgeLocalStop: async (campaignId) => {
        calls.push(['acknowledge', campaignId]);
        return {
          campaign_id: campaignId,
          emergency_stopped: true,
          local_stop_confirmed: true,
        };
      },
      localStopStatus: async (campaignId) => {
        calls.push(['status', campaignId]);
        return {
          campaign_id: campaignId,
          emergency_stopped: true,
          local_stop_confirmed: false,
        };
      },
    },
    getActiveCampaignIds: () => ['campaign_lab'],
    stopLocalCampaign: async (campaignId) => calls.push(['close', campaignId]),
  });

  await watcher.check();

  assert.deepEqual(calls, [
    ['status', 'campaign_lab'],
    ['close', 'campaign_lab'],
    ['acknowledge', 'campaign_lab'],
  ]);
  await watcher.stop();
});

test('watcher does not acknowledge a stop when local teardown fails', async () => {
  const calls = [];
  const watcher = createAutopilotEmergencyStopWatcher({
    apiClient: {
      acknowledgeLocalStop: async () => assert.fail('acknowledgement must not be sent'),
      localStopStatus: async () => ({
        campaign_id: 'campaign_lab',
        emergency_stopped: true,
        local_stop_confirmed: false,
      }),
    },
    getActiveCampaignIds: () => ['campaign_lab'],
    stopLocalCampaign: async () => {
      calls.push('close');
      throw new Error('local_runner_close_failed');
    },
  });

  await watcher.check();

  assert.deepEqual(calls, ['close']);
  await watcher.stop();
});
