"use client";

import { useCallback, useEffect } from "react";

import { getControlCenterOverview } from "@/lib/api";
import {
  createControlCenterLiveController,
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

function controlCenterEventsUrl(campaignId?: string): string {
  const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
  const url = new URL("/mythos/control-center/events", baseUrl);
  if (campaignId) {
    url.searchParams.set("campaign_id", campaignId);
  }
  return url.toString();
}

export function LiveControlCenter({
  campaignId,
  searchQuery,
  onConnectionState,
  onRefreshError,
  onSnapshot,
}: LiveControlCenterProps) {
  const refetch = useCallback(async (signal: AbortSignal) => {
    try {
      const response = await getControlCenterOverview(campaignId, signal);
      if (signal.aborted) {
        return;
      }
      onSnapshot(
        filterControlCenterSnapshot(mapControlCenterOverview(response), searchQuery),
      );
    } catch (error) {
      if (signal.aborted) {
        return;
      }
      onRefreshError(error instanceof Error ? error.message : "control_center_request_failed");
    }
  }, [campaignId, onRefreshError, onSnapshot, searchQuery]);

  useEffect(() => {
    const controller = createControlCenterLiveController({
      eventsUrl: controlCenterEventsUrl(campaignId),
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
