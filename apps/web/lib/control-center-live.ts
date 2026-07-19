export type ControlCenterLiveState = "connecting" | "live" | "degraded" | "paused";

type EventListener = () => void;

export interface ControlCenterEventSource {
  addEventListener(type: string, listener: EventListener): void;
  removeEventListener(type: string, listener: EventListener): void;
  close(): void;
}

interface Scheduler {
  setInterval(callback: () => void, delay: number): number;
  clearInterval(id: number): void;
}

interface VisibilitySource {
  readonly state: "hidden" | "visible";
  addEventListener(type: "visibilitychange", listener: EventListener): void;
  removeEventListener(type: "visibilitychange", listener: EventListener): void;
}

interface ControlCenterLiveOptions {
  eventsUrl: string;
  eventSourceFactory(url: string): ControlCenterEventSource;
  refetch(signal: AbortSignal): Promise<void>;
  onStateChange(state: ControlCenterLiveState): void;
  scheduler: Scheduler;
  visibility: VisibilitySource;
  errorThreshold?: number;
  pollingIntervalMs?: number;
}

export interface ControlCenterLiveController {
  start(): void;
  stop(): void;
}

export async function executeControlCenterRefresh<T>({
  load,
  onRefreshError,
  publish,
  signal,
}: {
  load(signal: AbortSignal): Promise<T>;
  onRefreshError(message: string): void;
  publish(value: T): void;
  signal: AbortSignal;
}): Promise<void> {
  try {
    const value = await load(signal);
    if (!signal.aborted) {
      publish(value);
    }
  } catch (error) {
    if (signal.aborted) {
      return;
    }
    onRefreshError(error instanceof Error ? error.message : "control_center_request_failed");
    throw error;
  }
}

export function createControlCenterLiveController(
  options: ControlCenterLiveOptions,
): ControlCenterLiveController {
  const errorThreshold = options.errorThreshold ?? 2;
  const pollingIntervalMs = options.pollingIntervalMs ?? 5_000;
  let source: ControlCenterEventSource | null = null;
  let poller: number | null = null;
  let consecutiveErrors = 0;
  let started = false;
  let state: ControlCenterLiveState | null = null;
  let activeRefetch: AbortController | null = null;
  let pendingRefresh = false;
  let generation = 0;
  let openEpoch = 0;

  const setState = (nextState: ControlCenterLiveState) => {
    if (state !== nextState) {
      state = nextState;
      options.onStateChange(nextState);
    }
  };

  const stopPolling = () => {
    if (poller !== null) {
      options.scheduler.clearInterval(poller);
      poller = null;
    }
  };

  const cancelRefetch = () => {
    generation += 1;
    pendingRefresh = false;
    activeRefetch?.abort();
    activeRefetch = null;
  };

  const refetch = (queueIfBusy = false) => {
    if (!started || options.visibility.state === "hidden") {
      return;
    }
    if (activeRefetch !== null) {
      pendingRefresh ||= queueIfBusy;
      return;
    }
    const request = new AbortController();
    const requestGeneration = generation;
    const requestOpenEpoch = openEpoch;
    activeRefetch = request;
    const finish = () => {
      if (activeRefetch !== request) {
        return;
      }
      activeRefetch = null;
      if (
        pendingRefresh &&
        started &&
        options.visibility.state === "visible" &&
        generation === requestGeneration
      ) {
        pendingRefresh = false;
        refetch();
      }
    };
    void options.refetch(request.signal).then(finish, () => {
      if (
        !request.signal.aborted &&
        started &&
        generation === requestGeneration &&
        openEpoch === requestOpenEpoch
      ) {
        startPolling();
      }
      finish();
    });
  };

  const startPolling = () => {
    if (poller === null) {
      poller = options.scheduler.setInterval(() => {
        refetch();
      }, pollingIntervalMs);
    }
    setState("degraded");
  };

  const onOpen = () => {
    openEpoch += 1;
    consecutiveErrors = 0;
    stopPolling();
    setState("live");
    refetch(true);
  };
  const onError = () => {
    consecutiveErrors += 1;
    if (consecutiveErrors >= errorThreshold) {
      startPolling();
    }
  };
  const onInvalidated = () => {
    refetch(true);
  };

  const closeSource = () => {
    if (source === null) {
      return;
    }
    source.removeEventListener("open", onOpen);
    source.removeEventListener("error", onError);
    source.removeEventListener("control-center-invalidated", onInvalidated);
    source.close();
    source = null;
  };

  const connect = () => {
    if (!started || options.visibility.state === "hidden" || source !== null) {
      return;
    }
    setState("connecting");
    source = options.eventSourceFactory(options.eventsUrl);
    source.addEventListener("open", onOpen);
    source.addEventListener("error", onError);
    source.addEventListener("control-center-invalidated", onInvalidated);
  };

  const onVisibilityChange = () => {
    if (options.visibility.state === "hidden") {
      closeSource();
      stopPolling();
      cancelRefetch();
      consecutiveErrors = 0;
      setState("paused");
      return;
    }
    connect();
  };

  return {
    start() {
      if (started) {
        return;
      }
      started = true;
      options.visibility.addEventListener("visibilitychange", onVisibilityChange);
      if (options.visibility.state === "hidden") {
        setState("paused");
      } else {
        connect();
      }
    },
    stop() {
      if (!started) {
        return;
      }
      started = false;
      options.visibility.removeEventListener("visibilitychange", onVisibilityChange);
      closeSource();
      stopPolling();
      cancelRefetch();
    },
  };
}
