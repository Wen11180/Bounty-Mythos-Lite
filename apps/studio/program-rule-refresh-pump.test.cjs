const assert = require("node:assert/strict");
const test = require("node:test");

const {
  PROGRAM_RULE_PUMP_LIMITS,
  createProgramRuleRefreshPump,
} = require("./program-rule-refresh-pump.cjs");

const NOW = Date.parse("2026-07-18T12:00:00Z");

test("pump stays inert until start and schedules the API-provided due time", async () => {
  const harness = createPumpHarness({
    results: [status("idle", "2026-07-18T12:30:00Z", false)],
  });
  assert.equal(harness.calls.kick, 0);
  assert.equal(harness.timers.active.length, 0);

  const result = await harness.pump.start();

  assert.deepEqual(result, status("idle", "2026-07-18T12:30:00Z", false));
  assert.equal(harness.calls.kick, 1);
  assert.deepEqual(harness.timers.active.map(({ delay }) => delay), [30 * 60 * 1_000]);
});

test("start immediately catches overdue work and drains claimed jobs sequentially", async () => {
  const harness = createPumpHarness({
    results: [
      status("completed", "2026-07-18T11:59:00Z", true),
      status("failed", "2026-07-18T11:59:30Z", true),
      status("idle", "2026-07-18T12:05:00Z", false),
    ],
  });

  const result = await harness.pump.start();

  assert.deepEqual(result, status("idle", "2026-07-18T12:05:00Z", false));
  assert.equal(harness.calls.kick, 3);
  assert.equal(harness.calls.maxActive, 1);
  assert.deepEqual(harness.timers.active.map(({ delay }) => delay), [5 * 60 * 1_000]);
});

test("concurrent UI kicks coalesce and the wake delay is capped at one hour", async () => {
  const pending = deferred();
  const harness = createPumpHarness({ results: [pending.promise] });

  const first = harness.pump.start();
  const second = harness.pump.kick();
  assert.equal(first, second);
  assert.equal(harness.calls.kick, 1);

  pending.resolve(status("idle", "2026-07-18T15:00:00Z", false));
  await first;
  assert.deepEqual(harness.timers.active.map(({ delay }) => delay), [
    PROGRAM_RULE_PUMP_LIMITS.maxWakeMs,
  ]);
});

test("timer wakes run through the same coalesced drain path", async () => {
  const harness = createPumpHarness({
    results: [
      status("idle", "2026-07-18T12:00:01Z", false),
      status("idle", "2026-07-18T12:30:00Z", false),
    ],
  });
  await harness.pump.start();
  assert.equal(harness.timers.active.length, 1);

  await harness.timers.fireNext();

  assert.equal(harness.calls.kick, 2);
  assert.equal(harness.timers.active.length, 1);
  assert.equal(harness.timers.active[0].delay, 30 * 60 * 1_000);
});

test("close clears timers, closes active work, waits, and is memoized", async () => {
  const pending = deferred();
  const harness = createPumpHarness({
    closeRunner() {
      pending.resolve(status("failed", null, true));
      return Promise.resolve();
    },
    results: [pending.promise],
  });
  const running = harness.pump.start();
  const firstClose = harness.pump.close("app_exit");
  const secondClose = harness.pump.close("ignored");
  assert.equal(firstClose, secondClose);

  await firstClose;
  assert.equal((await running).status, "failed");
  assert.equal(harness.calls.close, 1);
  assert.equal(harness.timers.active.length, 0);
  await assert.rejects(harness.pump.kick(), safePumpError("program_rule_pump_closed"));
});

function createPumpHarness({ closeRunner = null, results }) {
  const calls = { active: 0, close: 0, kick: 0, maxActive: 0 };
  const queue = [...results];
  const timers = fakeTimers();
  const runner = {
    close(reason) {
      calls.close += 1;
      assert.equal(reason, "app_exit");
      return closeRunner ? closeRunner() : Promise.resolve();
    },
    async kick() {
      calls.kick += 1;
      calls.active += 1;
      calls.maxActive = Math.max(calls.maxActive, calls.active);
      try {
        assert.ok(queue.length > 0, "unexpected runner kick");
        return await queue.shift();
      } finally {
        calls.active -= 1;
      }
    },
  };
  const pump = createProgramRuleRefreshPump({
    clearTimer: timers.clear,
    now: () => NOW,
    runner,
    setTimer: timers.set,
  });
  return { calls, pump, timers };
}

function fakeTimers() {
  let nextId = 1;
  const active = [];
  return {
    active,
    clear(id) {
      const index = active.findIndex((timer) => timer.id === id);
      if (index !== -1) active.splice(index, 1);
    },
    async fireNext() {
      assert.ok(active.length > 0);
      const timer = active.shift();
      return timer.callback();
    },
    set(callback, delay) {
      const id = nextId;
      nextId += 1;
      active.push({ callback, delay, id });
      return id;
    },
  };
}

function status(value, nextDueAt, processed) {
  return { next_due_at: nextDueAt, processed, status: value };
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function safePumpError(code) {
  return (error) => {
    assert.equal(error?.code, code);
    assert.equal(error?.message, code);
    return true;
  };
}
