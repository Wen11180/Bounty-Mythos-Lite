"use client";

import { useCallback, useEffect } from "react";

import { getControlCenterOverview, getRuntimeApiBaseUrl } from "@/lib/api";
import {
  buildControlCenterEventsUrl,
  createControlCenterLiveController,
  executeControlCenterRefresh,
  type ControlCenterLiveState,
} from "@/lib/control-center-live";
import {
  filterControlCenterSnapshot,
  mapControlCenterOverview,
  type ControlCenterSnapshot,
} from "@/lib/control-center-data";

interface LiveControlCenterProps {
  campaignId?: string;
  searchQuery: string;
  onConnectionState(state: ControlCenterLiveState): void;
  onRefreshError(message: string): void;
  onSnapshot(snapshot: ControlCenterSnapshot): void;
}

export function LiveControlCenter({
  campaignId,
  searchQuery,
  onConnectionState,
  onRefreshError,
  onSnapshot,
}: LiveControlCenterProps) {
  const refetch = useCallback(
    (signal: AbortSignal) => executeControlCenterRefresh({
      load: async (requestSignal) => filterControlCenterSnapshot(
        mapControlCenterOverview(await getControlCenterOverview(campaignId, requestSignal)),
        searchQuery,
      ),
      onRefreshError,
      publish: onSnapshot,
      signal,
    }),
    [campaignId, onRefreshError, onSnapshot, searchQuery],
  );

  useEffect(() => {
    const controller = createControlCenterLiveController({
      eventsUrl: buildControlCenterEventsUrl(getRuntimeApiBaseUrl(), campaignId),
      eventSourceFactory: (url) => new EventSource(url),
      onStateChange: onConnectionState,
      refetch,
      scheduler: {
        clearInterval: (id) => window.clearInterval(id),
        setInterval: (callback, delay) => window.setInterval(callback, delay),
      },
      visibility: {
        addEventListener: (_type, listener) =>
          document.addEventListener("visibilitychange", listener),
        get state() {
          return document.visibilityState === "hidden" ? "hidden" : "visible";
        },
        removeEventListener: (_type, listener) =>
          document.removeEventListener("visibilitychange", listener),
      },
    });
    controller.start();
    return () => controller.stop();
  }, [campaignId, onConnectionState, refetch]);

  return null;
}
