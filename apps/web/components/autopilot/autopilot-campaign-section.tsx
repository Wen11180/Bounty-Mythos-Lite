"use client";

import { useCallback, useEffect, useState } from "react";

import { AutopilotPanel } from "@/components/autopilot/autopilot-panel";
import {
  getAutopilotCampaignProjection,
  getRuntimeApiBaseUrl,
  postAutopilotApprovalDecision,
  postAutopilotEmergencyStop,
  postAutopilotSteering,
  prepareAutopilotEmergencyStop,
  type AutopilotEmergencyStopPreparation,
  type AutopilotSteeringRequest,
} from "@/lib/api";
import {
  parseAutopilotCampaignProjection,
  type AutopilotCampaignProjection,
} from "@/lib/autopilot-data";
import {
  buildControlCenterEventsUrl,
  createControlCenterLiveController,
  executeControlCenterRefresh,
  type ControlCenterLiveState,
} from "@/lib/control-center-live";

type AutopilotCampaignSectionProps = {
  campaignId: string;
};

const liveStateLabels: Record<ControlCenterLiveState, string> = {
  connecting: "Connecting",
  live: "Live",
  degraded: "Degraded · polling",
  paused: "Paused while hidden",
};

export function AutopilotCampaignSection({
  campaignId,
}: AutopilotCampaignSectionProps) {
  const [projection, setProjection] = useState<AutopilotCampaignProjection | null>(null);
  const [connectionState, setConnectionState] =
    useState<ControlCenterLiveState>("connecting");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadProjection = useCallback(
    async (requestSignal: AbortSignal) =>
      parseAutopilotCampaignProjection(
        await getAutopilotCampaignProjection(campaignId, requestSignal),
        campaignId,
      ),
    [campaignId],
  );

  const refresh = useCallback(
    (signal: AbortSignal) =>
      executeControlCenterRefresh({
        load: loadProjection,
        onRefreshError: () => {
          setError("Projection refresh failed; the last known good state is retained.");
        },
        publish: (next) => {
          setProjection(next);
          setError(null);
        },
        signal,
      }),
    [loadProjection],
  );

  useEffect(() => {
    const initialRequest = new AbortController();
    void refresh(initialRequest.signal).catch(() => undefined);

    const controller = createControlCenterLiveController({
      eventsUrl: buildControlCenterEventsUrl(getRuntimeApiBaseUrl(), campaignId),
      eventSourceFactory: (url) => new EventSource(url),
      onStateChange: setConnectionState,
      refetch: refresh,
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
    return () => {
      initialRequest.abort();
      controller.stop();
    };
  }, [campaignId, refresh]);

  async function withBusy(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      await refresh(new AbortController().signal);
    } catch {
      setError("Command failed; the last known good state is retained.");
    } finally {
      setBusy(false);
    }
  }

  async function prepareEmergencyStop(): Promise<AutopilotEmergencyStopPreparation | null> {
    setBusy(true);
    setError(null);
    try {
      const prepared = await prepareAutopilotEmergencyStop(campaignId, {
        actor: "operator",
        reason: "operator_emergency_stop",
      });
      if (
        typeof prepared.confirmation_nonce !== "string" ||
        prepared.confirmation_nonce.length === 0 ||
        prepared.confirmation_nonce.length > 256 ||
        typeof prepared.expires_at !== "string" ||
        !Number.isFinite(Date.parse(prepared.expires_at)) ||
        Date.parse(prepared.expires_at) <= Date.now()
      ) {
        throw new Error("invalid_emergency_stop_preparation");
      }
      return prepared;
    } catch {
      setError("Emergency-stop preparation failed; no stop command was sent.");
      return null;
    } finally {
      setBusy(false);
    }
  }

  const renderedProjection = projection ?? undefined;
  if (renderedProjection?.campaign_mode === "legacy") {
    return null;
  }

  return (
    <div className="grid gap-2" data-testid="autopilot-campaign-section">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[var(--muted)]">
        <span
          data-state={connectionState}
          data-testid="autopilot-live-state"
          role="status"
        >
          Autopilot state · {liveStateLabels[connectionState]}
        </span>
        {error ? (
          <span className="text-[var(--danger)]" data-testid="autopilot-error">
            {error}
          </span>
        ) : null}
      </div>
      {renderedProjection ? (
        <AutopilotPanel
          projection={renderedProjection}
          busy={busy}
          onPrepareEmergencyStop={prepareEmergencyStop}
          onEmergencyStop={(confirmationNonce) =>
            withBusy(async () => {
              const stopped = await postAutopilotEmergencyStop(campaignId, {
                actor: "operator",
                confirmation_nonce: confirmationNonce,
                reason: "operator_emergency_stop",
              });
              if (stopped.emergency_stopped !== true) {
                throw new Error("emergency_stop_not_committed");
              }
              const revokeLocal = window.mythosStudio?.emergencyStopAutopilotLocal;
              if (revokeLocal) {
                const local = await revokeLocal({ campaignId });
                if (local.revoked !== true) {
                  throw new Error("local_session_revocation_failed");
                }
              }
            })
          }
          onSteer={(request: AutopilotSteeringRequest) =>
            withBusy(async () => {
              await postAutopilotSteering(campaignId, request);
            })
          }
          onApprovalDecision={(approvalId, decision) =>
            withBusy(async () => {
              await postAutopilotApprovalDecision(campaignId, approvalId, {
                decision,
                actor: "operator",
                reason: "operator_r3_decision",
              });
            })
          }
        />
      ) : (
        <p className="border border-[var(--line)] bg-white p-4 text-sm text-[var(--muted)]" role="status">
          Loading the safe Autopilot projection…
        </p>
      )}
    </div>
  );
}
