const assert = require("node:assert/strict");
const test = require("node:test");

const { createLocalResearchWakeup } = require("./local-research-wakeup.cjs");

const autonomousResearchCapability = "a".repeat(43);

test("local research wakeup delegates one bounded cycle to the shared coordinator", async () => {
  const calls = [];
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options });
      return jsonResponse(wakeupResult({
        status: "completed",
        processed_count: 2,
        outcome_counts: { dispatched: 2 },
      }));
    },
    getBaseUrl: () => "http://127.0.0.1:8000",
    getCapability: () => autonomousResearchCapability,
  });

  const result = await wakeup.wake();

  assert.deepEqual(result, wakeupResult({
    status: "completed",
    processed_count: 2,
    outcome_counts: { dispatched: 2 },
  }));
  assert.deepEqual(calls, [
    {
      url: "http://127.0.0.1:8000/mythos/campaigns/autonomous-wakeup",
      options: {
        method: "POST",
        redirect: "error",
        signal: calls[0].options.signal,
        headers: {
          "X-Mythos-Autonomous-Research-Capability": autonomousResearchCapability,
        },
      },
    },
  ]);
});

test("local research wakeup accepts an immediate coordinator handoff", async () => {
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async () => jsonResponse(wakeupResult({
      status: "accepted",
      stop_reason: "wakeup_accepted",
    })),
    getBaseUrl: () => "http://127.0.0.1:8000",
    getCapability: () => autonomousResearchCapability,
  });

  assert.deepEqual(await wakeup.wake(), wakeupResult({
    status: "accepted",
    stop_reason: "wakeup_accepted",
  }));
});

test("local research wakeup keeps a bounded coordinator submission deadline", async () => {
  const originalSetTimeout = global.setTimeout;
  const delays = [];
  global.setTimeout = (callback, delay, ...args) => {
    delays.push(delay);
    return originalSetTimeout(callback, delay, ...args);
  };
  try {
    const wakeup = createLocalResearchWakeup({
      fetchImpl: async () => jsonResponse(wakeupResult()),
      getBaseUrl: () => "http://127.0.0.1:8000",
      getCapability: () => autonomousResearchCapability,
    });

    await wakeup.wake();
  } finally {
    global.setTimeout = originalSetTimeout;
  }

  assert.deepEqual(delays, [5_000]);
});

test("local research wakeup uses a 60-second minimum cadence and stops cleanly", async () => {
  const timers = [];
  const cleared = [];
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async () => jsonResponse(wakeupResult()),
    getBaseUrl: () => "http://127.0.0.1:8000",
    getCapability: () => autonomousResearchCapability,
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

test("local research wakeup stops in-flight shared coordination before it can advance work", async () => {
  const calls = [];
  const errors = [];
  const timers = [];
  let resolveWake;
  const sharedWake = new Promise((resolve) => {
    resolveWake = resolve;
  });
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options });
      return sharedWake;
    },
    getBaseUrl: () => "http://127.0.0.1:8000",
    getCapability: () => autonomousResearchCapability,
    setIntervalImpl: (callback, delay) => {
      timers.push({ callback, delay });
      return "timer-1";
    },
    clearIntervalImpl: () => {},
    onError: (error) => errors.push(error),
  });

  const stop = wakeup.start();
  const stopping = stop();
  resolveWake(jsonResponse(wakeupResult()));
  await stopping;
  timers[0].callback();
  await Promise.resolve();

  assert.deepEqual(calls.map((call) => call.options.method), ["POST"]);
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
    getCapability: () => autonomousResearchCapability,
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
    getCapability: () => autonomousResearchCapability,
  });

  await assert.rejects(wakeup.wake(), /local_research_wakeup_response_too_large/);
  assert.equal(textCalled, false);
  assert.equal(canceled, true);
});

test("local research wakeup accepts a shared lease-held result without a second tick", async () => {
  const calls = [];
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options });
      return jsonResponse(wakeupResult({
        status: "lease_held",
        stop_reason: "wakeup_lease_held",
      }));
    },
    getBaseUrl: () => "http://127.0.0.1:8000",
    getCapability: () => autonomousResearchCapability,
  });

  assert.deepEqual(await wakeup.wake(), wakeupResult({
    status: "lease_held",
    stop_reason: "wakeup_lease_held",
  }));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://127.0.0.1:8000/mythos/campaigns/autonomous-wakeup");
  assert.equal(calls[0].options.method, "POST");
});

test("local research wakeup rejects a malformed shared coordinator response", async () => {
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async () => jsonResponse({ status: "completed", processed_count: 1 }),
    getBaseUrl: () => "http://127.0.0.1:8000",
    getCapability: () => autonomousResearchCapability,
  });

  await assert.rejects(wakeup.wake(), /local_research_wakeup_response_invalid/);
});

test("local research wakeup requires an unexposed local capability before requesting", async () => {
  let fetchCalled = false;
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async () => {
      fetchCalled = true;
      return jsonResponse(wakeupResult());
    },
    getBaseUrl: () => "http://127.0.0.1:8000",
    getCapability: () => "not-a-capability",
  });

  await assert.rejects(wakeup.wake(), /local_research_wakeup_capability_required/);
  assert.equal(fetchCalled, false);
});

test("local research wakeup accepts a shared not-due result", async () => {
  const wakeup = createLocalResearchWakeup({
    fetchImpl: async () => jsonResponse(wakeupResult({
      status: "not_due",
      stop_reason: "wakeup_not_due",
    })),
    getBaseUrl: () => "http://127.0.0.1:8000",
    getCapability: () => autonomousResearchCapability,
  });

  assert.deepEqual(await wakeup.wake(), wakeupResult({
    status: "not_due",
    stop_reason: "wakeup_not_due",
  }));
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

function wakeupResult(overrides = {}) {
  return {
    status: "completed",
    stop_reason: null,
    processed_count: 0,
    outcome_counts: {},
    execution_allowed: false,
    dispatch_allowed: false,
    validation_allowed: false,
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
    ...overrides,
  };
}
