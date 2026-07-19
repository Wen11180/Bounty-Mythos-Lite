const assert = require("node:assert/strict");
const test = require("node:test");

const { createLocalResearchWakeup } = require("./local-research-wakeup.cjs");

const campaignId = "campaign_0123456789abcdef0123456789abcdef";

test("local research wakeup ticks only eligible local campaigns", async () => {
  const calls = [];
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options });
      if (options.method === "GET") {
        return jsonResponse([
          {
            id: campaignId,
            autonomy_level: "level_0_read_only",
            scope_status: "in_scope",
            status: "running",
          },
          {
            id: "campaign_11111111111111111111111111111111",
            autonomy_level: "level_0_read_only",
            scope_status: "in_scope",
            status: "paused",
          },
          {
            id: "campaign_11111111111111111111111111111112",
            autonomy_level: "level_0_read_only",
            scope_status: "in_scope",
            status: "awaiting_review",
          },
          {
            id: "campaign_22222222222222222222222222222222",
            autonomy_level: "level_0_read_only",
            scope_status: "out_of_scope",
            status: "running",
          },
          {
            id: "campaign_33333333333333333333333333333333",
            autonomy_level: "level_1_assisted",
            scope_status: "in_scope",
            status: "running",
          },
        ]);
      }
      return jsonResponse({
        status: "dispatched",
        validation_allowed: false,
        report_submission_allowed: false,
      });
    },
    getBaseUrl: () => "http://127.0.0.1:8000",
  });

  const results = await wakeup.wake();

  assert.deepEqual(results, [{ campaign_id: campaignId, status: "dispatched" }]);
  assert.deepEqual(calls, [
    {
      url: "http://127.0.0.1:8000/mythos/campaigns/autonomous-wakeup-candidates",
      options: { method: "GET", redirect: "error", signal: calls[0].options.signal },
    },
    {
      url: `http://127.0.0.1:8000/mythos/campaigns/${campaignId}/autonomous-research/tick`,
      options: { method: "POST", redirect: "error", signal: calls[1].options.signal },
    },
  ]);
});

test("local research wakeup uses a 60-second minimum cadence and stops cleanly", async () => {
  const timers = [];
  const cleared = [];
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async () => jsonResponse([]),
    getBaseUrl: () => "http://127.0.0.1:8000",
    setIntervalImpl: (callback, delay) => {
      timers.push({ callback, delay });
      return "timer-1";
    },
    clearIntervalImpl: (timer) => cleared.push(timer),
  });

  const stop = wakeup.start();
  await stop();

  assert.equal(timers.length, 1);
  assert.equal(timers[0].delay, 60_000);
  assert.deepEqual(cleared, ["timer-1"]);
});

test("local research wakeup stops in-flight work before it can tick a campaign", async () => {
  const calls = [];
  const errors = [];
  const timers = [];
  let resolveCampaigns;
  const campaigns = new Promise((resolve) => {
    resolveCampaigns = resolve;
  });
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options });
      if (options.method === "GET") {
        return campaigns;
      }
      return jsonResponse({ status: "dispatched" });
    },
    getBaseUrl: () => "http://127.0.0.1:8000",
    setIntervalImpl: (callback, delay) => {
      timers.push({ callback, delay });
      return "timer-1";
    },
    clearIntervalImpl: () => {},
    onError: (error) => errors.push(error),
  });

  const stop = wakeup.start();
  const stopping = stop();
  resolveCampaigns(jsonResponse([
    {
      id: campaignId,
      autonomy_level: "level_0_read_only",
      scope_status: "in_scope",
      status: "running",
    },
  ]));
  await stopping;
  timers[0].callback();
  await Promise.resolve();

  assert.deepEqual(calls.map((call) => call.options.method), ["GET"]);
  assert.deepEqual(errors, []);
});

test("local research wakeup rejects a non-loopback API origin before requesting it", async () => {
  let fetchCalled = false;
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async () => {
      fetchCalled = true;
      return jsonResponse([]);
    },
    getBaseUrl: () => "https://api.example.test",
  });

  await assert.rejects(wakeup.wake(), /exact_loopback_api_origin_required/);
  assert.equal(fetchCalled, false);
});

test("local research wakeup enforces the response cap while streaming", async () => {
  let textCalled = false;
  let canceled = false;
  const chunks = [
    Buffer.alloc(40 * 1024, 0x61),
    Buffer.alloc(40 * 1024, 0x62),
  ];
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async () => ({
      body: {
        getReader() {
          let index = 0;
          return {
            async cancel() {
              canceled = true;
            },
            async read() {
              if (index >= chunks.length) {
                return { done: true, value: undefined };
              }
              return { done: false, value: chunks[index++] };
            },
            releaseLock() {},
          };
        },
      },
      ok: true,
      async text() {
        textCalled = true;
        throw new Error("unbounded_text_buffering_forbidden");
      },
    }),
    getBaseUrl: () => "http://127.0.0.1:8000",
  });

  await assert.rejects(wakeup.wake(), /local_research_wakeup_response_too_large/);
  assert.equal(textCalled, false);
  assert.equal(canceled, true);
});

test("local research wakeup isolates one failed campaign and continues", async () => {
  const failedCampaignId = "campaign_11111111111111111111111111111111";
  const malformedCampaignId = "campaign_22222222222222222222222222222222";
  const successfulCampaignId = "campaign_33333333333333333333333333333333";
  const errors = [];
  const ticked = [];
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async (url, options = {}) => {
      if (options.method === "GET") {
        return jsonResponse([
          eligibleCampaign(failedCampaignId),
          eligibleCampaign(malformedCampaignId),
          eligibleCampaign(successfulCampaignId),
        ]);
      }
      ticked.push(url);
      if (url.includes(failedCampaignId)) {
        return { ...jsonResponse({ detail: "synthetic_failure" }), ok: false };
      }
      if (url.includes(malformedCampaignId)) {
        return jsonResponse({ detail: "missing_status" });
      }
      return jsonResponse({ status: "dispatched" });
    },
    getBaseUrl: () => "http://127.0.0.1:8000",
    onError: (error) => errors.push(error.message),
  });

  const results = await wakeup.wake();

  assert.deepEqual(results, [
    { campaign_id: successfulCampaignId, status: "dispatched" },
  ]);
  assert.deepEqual(ticked, [
    `http://127.0.0.1:8000/mythos/campaigns/${failedCampaignId}/autonomous-research/tick`,
    `http://127.0.0.1:8000/mythos/campaigns/${malformedCampaignId}/autonomous-research/tick`,
    `http://127.0.0.1:8000/mythos/campaigns/${successfulCampaignId}/autonomous-research/tick`,
  ]);
  assert.deepEqual(errors, [
    "local_research_campaign_tick_failed",
    "local_research_campaign_tick_failed",
  ]);
});

test("local research wakeup caps failed tick attempts at twenty", async () => {
  const campaigns = Array.from({ length: 21 }, (_, index) => (
    eligibleCampaign(`campaign_${index.toString(16).padStart(32, "0")}`)
  ));
  let tickCount = 0;
  let errorCount = 0;
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async (_url, options = {}) => {
      if (options.method === "GET") {
        return jsonResponse(campaigns);
      }
      tickCount += 1;
      return { ...jsonResponse({ detail: "synthetic_failure" }), ok: false };
    },
    getBaseUrl: () => "http://127.0.0.1:8000",
    onError: () => {
      errorCount += 1;
    },
  });

  assert.deepEqual(await wakeup.wake(), []);
  assert.equal(tickCount, 20);
  assert.equal(errorCount, 20);
});

test("local research wakeup advances through bounded campaign pages", async () => {
  const campaigns = Array.from({ length: 25 }, (_, index) => (
    eligibleCampaign(`campaign_${index.toString(16).padStart(32, "0")}`)
  ));
  const getUrls = [];
  const tickedCampaignIds = [];
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async (url, options = {}) => {
      if (options.method === "GET") {
        getUrls.push(url);
        const afterId = new URL(url).searchParams.get("after_id");
        const startIndex = afterId === null
          ? 0
          : campaigns.findIndex((campaign) => campaign.id === afterId) + 1;
        return jsonResponse(campaigns.slice(startIndex, startIndex + 20));
      }
      tickedCampaignIds.push(url.match(/campaign_[0-9a-f]{32}/u)[0]);
      return jsonResponse({ status: "dispatched" });
    },
    getBaseUrl: () => "http://127.0.0.1:8000",
  });

  await wakeup.wake();
  await wakeup.wake();
  await wakeup.wake();

  assert.deepEqual(tickedCampaignIds, campaigns.map((campaign) => campaign.id));
  assert.deepEqual(getUrls, [
    "http://127.0.0.1:8000/mythos/campaigns/autonomous-wakeup-candidates",
    `http://127.0.0.1:8000/mythos/campaigns/autonomous-wakeup-candidates?after_id=${campaigns[19].id}`,
    `http://127.0.0.1:8000/mythos/campaigns/autonomous-wakeup-candidates?after_id=${campaigns[24].id}`,
  ]);
});

function jsonResponse(value) {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  return {
    body: {
      getReader() {
        let consumed = false;
        return {
          async cancel() {},
          async read() {
            if (consumed) {
              return { done: true, value: undefined };
            }
            consumed = true;
            return { done: false, value: body };
          },
          releaseLock() {},
        };
      },
    },
    ok: true,
    text: async () => body.toString("utf8"),
  };
}

function eligibleCampaign(id) {
  return {
    id,
    autonomy_level: "level_0_read_only",
    scope_status: "in_scope",
    status: "running",
  };
}
