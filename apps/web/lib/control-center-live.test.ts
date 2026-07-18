import assert from "node:assert/strict";
import test from "node:test";

import {
  createControlCenterLiveController,
  type ControlCenterEventSource,
  type ControlCenterLiveState,
} from "./control-center-live.ts";

type Listener = () => void;

class FakeEventSource implements ControlCenterEventSource {
  readonly listeners = new Map<string, Set<Listener>>();
  closed = false;

  addEventListener(type: string, listener: Listener) {
    const listeners = this.listeners.get(type) ?? new Set<Listener>();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type: string, listener: Listener) {
    this.listeners.get(type)?.delete(listener);
  }

  close() {
    this.closed = true;
  }

  emit(type: string) {
    for (const listener of this.listeners.get(type) ?? []) {
      listener();
    }
  }
}

function liveHarness(options: { refetch?: (signal?: AbortSignal) => Promise<void> } = {}) {
  const sources: Array<{ source: FakeEventSource; url: string }> = [];
  const states: ControlCenterLiveState[] = [];
  const intervals = new Map<number, () => void>();
  const visibilityListeners = new Set<Listener>();
  let nextIntervalId = 1;
  let visibilityState: "hidden" | "visible" = "visible";
  let refetches = 0;

  const controller = createControlCenterLiveController({
    eventSourceFactory(url) {
      const source = new FakeEventSource();
      sources.push({ source, url });
      return source;
    },
    eventsUrl: "http://127.0.0.1:8000/mythos/control-center/events?campaign_id=campaign_1",
    onStateChange(state) {
      states.push(state);
    },
    refetch: async (signal?: AbortSignal) => {
      refetches += 1;
      await options.refetch?.(signal);
    },
    scheduler: {
      clearInterval(id) {
        intervals.delete(id);
      },
      setInterval(callback, delay) {
        assert.equal(delay, 5_000);
        const id = nextIntervalId++;
        intervals.set(id, callback);
        return id;
      },
    },
    visibility: {
      addEventListener(_type, listener) {
        visibilityListeners.add(listener);
      },
      get state() {
        return visibilityState;
      },
      removeEventListener(_type, listener) {
        visibilityListeners.delete(listener);
      },
    },
  });

  return {
    controller,
    intervals,
    refetches: () => refetches,
    setVisibility(state: "hidden" | "visible") {
      visibilityState = state;
      for (const listener of visibilityListeners) {
        listener();
      }
    },
    sources,
    states,
    visibilityListeners,
  };
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

async function flushAsyncWork() {
  for (let index = 0; index < 4; index += 1) {
    await Promise.resolve();
  }
}

test("live controller opens one native EventSource and refreshes only on named invalidation", async () => {
  const harness = liveHarness();
  harness.controller.start();

  assert.equal(harness.sources.length, 1);
  assert.equal(harness.sources[0]?.url.includes("campaign_id=campaign_1"), true);
  assert.deepEqual(harness.states, ["connecting"]);

  harness.sources[0]?.source.emit("open");
  await Promise.resolve();
  harness.sources[0]?.source.emit("message");
  assert.equal(harness.refetches(), 1);
  harness.sources[0]?.source.emit("control-center-invalidated");
  await Promise.resolve();

  assert.equal(harness.refetches(), 2);
  assert.equal(harness.states.at(-1), "live");
  assert.equal(harness.intervals.size, 0);
});

test("live controller leaves reconnect to EventSource and starts one degraded poller", async () => {
  const harness = liveHarness();
  harness.controller.start();
  const source = harness.sources[0]?.source;
  source?.emit("error");

  assert.equal(harness.sources.length, 1);
  assert.equal(harness.intervals.size, 0);

  source?.emit("error");
  source?.emit("error");
  assert.equal(harness.sources.length, 1);
  assert.equal(harness.intervals.size, 1);
  assert.equal(harness.states.at(-1), "degraded");

  [...harness.intervals.values()][0]?.();
  assert.equal(harness.refetches(), 1);
  source?.emit("open");
  await flushAsyncWork();
  assert.equal(harness.intervals.size, 0);
  assert.equal(harness.states.at(-1), "live");
  assert.equal(harness.refetches(), 2);
});

test("live controller pauses hidden work, resumes with one source, and cleans up", () => {
  const harness = liveHarness();
  harness.controller.start();
  const first = harness.sources[0]?.source;
  first?.emit("error");
  first?.emit("error");
  assert.equal(harness.intervals.size, 1);

  harness.setVisibility("hidden");
  assert.equal(first?.closed, true);
  assert.equal(harness.intervals.size, 0);
  assert.equal(harness.states.at(-1), "paused");

  harness.setVisibility("visible");
  assert.equal(harness.sources.length, 2);
  assert.equal(harness.states.at(-1), "connecting");
  harness.setVisibility("visible");
  assert.equal(harness.sources.length, 2);

  harness.controller.stop();
  assert.equal(harness.sources[1]?.source.closed, true);
  assert.equal(harness.intervals.size, 0);
  assert.equal(harness.visibilityListeners.size, 0);
});

test("degraded polling keeps at most one refetch in flight", async () => {
  const request = deferred();
  const harness = liveHarness({ refetch: () => request.promise });
  harness.controller.start();
  harness.sources[0]?.source.emit("error");
  harness.sources[0]?.source.emit("error");
  const poll = [...harness.intervals.values()][0];

  poll?.();
  poll?.();
  assert.equal(harness.refetches(), 1);

  request.resolve();
  await request.promise;
  await Promise.resolve();
  poll?.();
  assert.equal(harness.refetches(), 2);
});

test("a refetch finishing after pause cannot publish into a newer generation", async () => {
  const request = deferred();
  const published: string[] = [];
  const harness = liveHarness({
    refetch: async (signal) => {
      await request.promise;
      if (!signal?.aborted) {
        published.push("stale snapshot");
      }
    },
  });
  harness.controller.start();
  harness.sources[0]?.source.emit("error");
  harness.sources[0]?.source.emit("error");
  [...harness.intervals.values()][0]?.();

  harness.setVisibility("hidden");
  harness.setVisibility("visible");
  request.resolve();
  await request.promise;
  await Promise.resolve();

  assert.deepEqual(published, []);
  assert.equal(harness.states.at(-1), "connecting");
});

test("invalidations during an active refetch coalesce into one follow-up refresh", async () => {
  const first = deferred();
  const second = deferred();
  let requestIndex = 0;
  const harness = liveHarness({
    refetch: () => [first.promise, second.promise][requestIndex++] ?? Promise.resolve(),
  });
  harness.controller.start();
  const source = harness.sources[0]?.source;

  source?.emit("control-center-invalidated");
  source?.emit("control-center-invalidated");
  source?.emit("control-center-invalidated");
  assert.equal(harness.refetches(), 1);

  first.resolve();
  await first.promise;
  await flushAsyncWork();
  assert.equal(harness.refetches(), 2);

  second.resolve();
  await second.promise;
  await Promise.resolve();
  assert.equal(harness.refetches(), 2);
});

test("open keeps an in-flight degraded refresh and queues one recovery refresh", async () => {
  const first = deferred();
  const second = deferred();
  const signals: AbortSignal[] = [];
  const published: string[] = [];
  let requestIndex = 0;
  const harness = liveHarness({
    refetch: async (signal) => {
      assert.ok(signal);
      signals.push(signal);
      await [first.promise, second.promise][requestIndex++];
      if (!signal.aborted) {
        published.push(`snapshot-${requestIndex}`);
      }
    },
  });
  harness.controller.start();
  const source = harness.sources[0]?.source;
  source?.emit("error");
  source?.emit("error");
  [...harness.intervals.values()][0]?.();

  source?.emit("open");
  assert.equal(signals[0]?.aborted, false);
  assert.equal(harness.states.at(-1), "live");
  assert.equal(harness.intervals.size, 0);

  first.resolve();
  await first.promise;
  await flushAsyncWork();
  assert.deepEqual(published, ["snapshot-1"]);
  assert.equal(harness.refetches(), 2);

  second.resolve();
  await second.promise;
  await Promise.resolve();
  harness.controller.stop();
});
