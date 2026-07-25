"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { AutopilotPanel } from "@/components/autopilot/autopilot-panel";
import {
  getAutopilotCampaignProjectionRequired,
  prepareAutopilotEmergencyStop,
  postAutopilotApprovalDecision,
  postAutopilotEmergencyStop,
  postAutopilotSteering,
} from "@/lib/api";
import {
  AUTOPILOT_PROJECTION_MAX_AGE_MS,
  classifyAutopilotProjectionFreshness,
  emptyAutopilotProjection,
  type AutopilotDataState,
  type AutopilotCampaignProjection,
} from "@/lib/autopilot-data";
import { formatLabel } from "@/lib/workbench-display";

const AUTOPILOT_PROJECTION_REFRESH_INTERVAL_MS = 30_000;

type AutopilotCampaignSectionProps = {
  campaignId: string;
};

export function AutopilotCampaignSection({
  campaignId,
}: AutopilotCampaignSectionProps) {
  const [projection, setProjection] = useState<AutopilotCampaignProjection>(
    () => emptyAutopilotProjection(campaignId),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ campaignId: string; message: string } | null>(null);
  const [dataState, setDataState] = useState<AutopilotDataState>("unavailable");
  const liveProjectionCampaignRef = useRef<string | null>(null);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    try {
      const next = await getAutopilotCampaignProjectionRequired<AutopilotCampaignProjection>(
        campaignId,
        signal,
      );
      if (signal?.aborted) {
        return;
      }
      setProjection(next);
      liveProjectionCampaignRef.current = campaignId;
      setDataState(
        classifyAutopilotProjectionFreshness(next) === "fresh" ? "live" : "stale",
      );
      setError(null);
    } catch (err) {
      if (signal?.aborted) {
        return;
      }
      setDataState(liveProjectionCampaignRef.current === campaignId ? "stale" : "unavailable");
      throw err;
    }
  }, [campaignId]);

  useEffect(() => {
    const controller = new AbortController();
    let refreshInFlight = false;

    liveProjectionCampaignRef.current = null;

    const refreshInBackground = () => {
      if (refreshInFlight) {
        return;
      }
      refreshInFlight = true;
      void refresh(controller.signal)
        .catch((err) => {
          if (!controller.signal.aborted) {
            setError({
              campaignId,
              message: err instanceof Error ? err.message : "projection_unavailable",
            });
          }
        })
        .finally(() => {
          refreshInFlight = false;
        });
    };

    refreshInBackground();
    const interval = window.setInterval(
      refreshInBackground,
      AUTOPILOT_PROJECTION_REFRESH_INTERVAL_MS,
    );
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [campaignId, refresh]);

  const projectionMatchesCampaign = projection.campaign_id === campaignId;
  const displayedProjection = projectionMatchesCampaign
    ? projection
    : emptyAutopilotProjection(campaignId);
  const displayedDataState =
    !projectionMatchesCampaign
      ? "unavailable"
      : dataState === "live"
          && classifyAutopilotProjectionFreshness(projection) !== "fresh"
        ? "stale"
        : dataState;

  useEffect(() => {
    if (!projectionMatchesCampaign || dataState !== "live") {
      return;
    }
    const generatedAt = Date.parse(projection.projection_generated_at ?? "");
    if (!Number.isFinite(generatedAt)) {
      return;
    }
    const remainingMs = generatedAt + AUTOPILOT_PROJECTION_MAX_AGE_MS - Date.now();
    if (remainingMs <= 0) {
      return;
    }
    const timeout = window.setTimeout(() => setDataState("stale"), remainingMs);
    return () => window.clearTimeout(timeout);
  }, [campaignId, dataState, projection.projection_generated_at, projectionMatchesCampaign]);

  async function withBusy(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      await refresh();
    } catch (err) {
      setError({
        campaignId,
        message: err instanceof Error ? err.message : "action_failed",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-2" data-testid="autopilot-campaign-section">
      {error?.campaignId === campaignId ? (
        <p className="text-xs text-rose-400" data-testid="autopilot-error">
          {formatLabel(error.message)}
        </p>
      ) : null}
      <AutopilotPanel
        projection={displayedProjection}
        busy={busy}
        dataState={displayedDataState}
        onEmergencyStop={() =>
          withBusy(async () => {
            const actor = "operator";
            const reason = "operator_emergency_stop";
            const confirmation = await prepareAutopilotEmergencyStop(campaignId, {
              actor,
              reason,
            });
            if (!window.confirm("确认紧急停止当前活动，并撤销所有生效租约？")) {
              return;
            }
            await postAutopilotEmergencyStop(campaignId, {
              actor,
              reason,
              confirmation_nonce: confirmation.confirmation_nonce,
            });
            // The server revokes leases first; the local watcher owns teardown and acknowledgement.
            const localStopTracking = window.mythosStudio?.emergencyStopAutopilotLocal?.(campaignId);
            void localStopTracking?.catch(() => undefined);
          })
        }
        onSteer={(branchId, priority, guidance) =>
          withBusy(async () => {
            await postAutopilotSteering(campaignId, {
              branch_id: branchId,
              priority,
              hypothesis_guidance: guidance,
              reason: "operator_steering",
            });
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
    </div>
  );
}
