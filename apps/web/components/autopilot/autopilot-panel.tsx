"use client";

import { useState } from "react";

import type {
  AutopilotEmergencyStopPreparation,
  AutopilotSteeringRequest,
} from "@/lib/api";
import {
  budgetMonitorRows,
  canDecideAutopilotApproval,
  orderAutopilotTimeline,
  summarizeAutopilotProjection,
  type AutopilotApprovalProjection,
  type AutopilotAssetProjection,
  type AutopilotBranchProjection,
  type AutopilotCampaignProjection,
  type AutopilotEventProjection,
} from "@/lib/autopilot-data";

type AutopilotPanelProps = {
  projection: AutopilotCampaignProjection;
  onPrepareEmergencyStop?: () => Promise<AutopilotEmergencyStopPreparation | null>;
  onEmergencyStop?: (confirmationNonce: string) => void;
  onSteer?: (request: AutopilotSteeringRequest) => void;
  onApprovalDecision?: (
    approvalId: string,
    decision: "approved" | "denied",
  ) => void;
  busy?: boolean;
};

function AgentGraph({
  branches,
  nextBranchId,
}: {
  branches: AutopilotBranchProjection[];
  nextBranchId: string | null;
}) {
  return (
    <PanelSection testId="autopilot-agent-graph" title="Agent Graph">
      <ul className="grid gap-2 text-xs text-[var(--muted)]">
        {branches.length === 0 ? (
          <li>No persisted specialist branches</li>
        ) : (
          branches.map((branch) => (
            <li className="grid gap-1" key={branch.branch_id}>
              <span className="font-mono text-[var(--foreground)]">
                {branch.branch_id} · {branch.specialist ?? "unassigned specialist"}
                {branch.branch_id === nextBranchId ? " · next" : ""}
              </span>
              <span>
                {branch.status} · priority {branch.priority}
                {branch.risk_tier ? ` · ${branch.risk_tier}` : ""}
              </span>
              <span>
                depends on {branch.dependencies.length > 0 ? branch.dependencies.join(", ") : "none"}
              </span>
              <span>
                handoff {branch.handoff_from ?? "origin"} → {branch.handoff_to ?? "pending"}
              </span>
            </li>
          ))
        )}
      </ul>
    </PanelSection>
  );
}

function AssetMap({ assets }: { assets: AutopilotAssetProjection[] }) {
  return (
    <PanelSection testId="autopilot-asset-map" title="Asset Map">
      <ul className="grid gap-2 text-xs text-[var(--muted)]">
        {assets.length === 0 ? (
          <li>No projected assets</li>
        ) : (
          assets.map((asset) => (
            <li className="grid gap-1" key={asset.asset_id}>
              <span className="font-mono text-[var(--foreground)]">
                {asset.alias ?? asset.asset_id}
              </span>
              <span>
                {asset.status}
                {asset.host ? ` · ${asset.host}` : ""}
                {asset.port ? `:${asset.port}` : ""}
              </span>
              {asset.reason ? <span>{asset.reason}</span> : null}
            </li>
          ))
        )}
      </ul>
    </PanelSection>
  );
}

function LiveTimeline({ events }: { events: AutopilotEventProjection[] }) {
  const ordered = orderAutopilotTimeline(events);
  return (
    <PanelSection testId="autopilot-live-timeline" title="Live Timeline">
      <ol className="grid gap-2 text-xs text-[var(--muted)]">
        {ordered.length === 0 ? (
          <li>No persisted events</li>
        ) : (
          ordered.map((event) => {
            const refs = Object.entries(event.refs);
            return (
              <li className="grid gap-1" key={event.event_id}>
                <span className="text-[var(--foreground)]">
                  {event.kind} · {event.summary}
                </span>
                {event.created_at ? <time dateTime={event.created_at}>{event.created_at}</time> : null}
                {refs.length > 0 ? (
                  <span className="font-mono text-[10px]">
                    {refs.map(([key, value]) => `${key}:${value}`).join(" · ")}
                  </span>
                ) : null}
              </li>
            );
          })
        )}
      </ol>
    </PanelSection>
  );
}

function ResearchQueue({
  branches,
  nextBranchId,
  nextReason,
}: {
  branches: AutopilotBranchProjection[];
  nextBranchId: string | null;
  nextReason: string | null;
}) {
  const queue = [...branches].sort((left, right) => {
    if (left.branch_id === nextBranchId) return -1;
    if (right.branch_id === nextBranchId) return 1;
    if (left.queue_rank !== null || right.queue_rank !== null) {
      return (left.queue_rank ?? Number.MAX_SAFE_INTEGER) -
        (right.queue_rank ?? Number.MAX_SAFE_INTEGER);
    }
    return right.priority - left.priority || left.branch_id.localeCompare(right.branch_id);
  });
  return (
    <PanelSection testId="autopilot-research-queue" title="Research Queue">
      <ol className="grid gap-2 text-xs text-[var(--muted)]">
        {queue.length === 0 ? (
          <li>No queued branches</li>
        ) : (
          queue.map((branch, index) => (
            <li className="grid gap-1" key={branch.branch_id}>
              <span className="font-mono text-[var(--foreground)]">
                {index + 1}. {branch.branch_id} · priority {branch.priority}
              </span>
              <span>
                {branch.branch_id === nextBranchId
                  ? nextReason ?? "highest ranked eligible branch"
                  : branch.reason ?? branch.status}
              </span>
            </li>
          ))
        )}
      </ol>
    </PanelSection>
  );
}

function BudgetMonitor({
  budgets,
}: {
  budgets: AutopilotCampaignProjection["budgets"];
}) {
  return (
    <PanelSection testId="autopilot-budget-monitor" title="Budget Monitor">
      <dl className="grid grid-cols-1 gap-2 text-xs text-[var(--muted)] sm:grid-cols-2">
        {budgetMonitorRows(budgets).map((row) => (
          <div key={row.label}>
            <dt>{row.label}</dt>
            <dd className="font-mono text-[var(--foreground)]">{row.value}</dd>
          </div>
        ))}
      </dl>
    </PanelSection>
  );
}

function ApprovalInbox({
  approvals,
  onApprovalDecision,
  busy,
}: {
  approvals: AutopilotApprovalProjection[];
  onApprovalDecision?: (
    approvalId: string,
    decision: "approved" | "denied",
  ) => void;
  busy?: boolean;
}) {
  return (
    <PanelSection testId="autopilot-approval-inbox" title="Approval Inbox">
      <ul className="grid gap-4 text-xs text-[var(--muted)]">
        {approvals.length === 0 ? (
          <li>No projected approvals</li>
        ) : (
          approvals.map((approval) => {
            const decision = canDecideAutopilotApproval(approval);
            return (
              <li
                className="grid gap-2 border-l-2 border-[var(--line)] pl-3"
                data-testid={`autopilot-approval-${approval.approval_id}`}
                key={approval.approval_id}
              >
                <div>
                  <span className="font-mono text-[var(--foreground)]">
                    {approval.approval_id}
                  </span>
                  <span> · {approval.status}</span>
                  {approval.risk_tier ? <span> · {approval.risk_tier}</span> : null}
                </div>
                {approval.plan_digest ? (
                  <div className="break-all font-mono text-[10px]">
                    plan {approval.plan_digest}
                  </div>
                ) : null}
                <div className="grid gap-1" data-testid={`autopilot-exact-diff-${approval.approval_id}`}>
                  <span className="font-semibold text-[var(--foreground)]">Exact R3 plan diff</span>
                  {approval.exact_diff.length === 0 ? (
                    <span>No exact diff available</span>
                  ) : (
                    <dl className="grid gap-2">
                      {approval.exact_diff.map((diff, index) => (
                        <div
                          className="grid grid-cols-[minmax(0,0.8fr)_minmax(0,1fr)_auto_minmax(0,1fr)] gap-2"
                          key={`${diff.field}-${index}`}
                        >
                          <dt className="break-words font-semibold">{diff.field}</dt>
                          <dd className="break-words font-mono">{diff.before}</dd>
                          <span aria-hidden="true">→</span>
                          <dd className="break-words font-mono">{diff.after}</dd>
                        </div>
                      ))}
                    </dl>
                  )}
                </div>
                {!decision.allowed ? (
                  <div className="text-[var(--warning)]">{decision.reason}</div>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    <button
                      className="min-h-9 rounded-md bg-[var(--accent)] px-3 font-semibold text-white disabled:opacity-50"
                      data-testid={`autopilot-approval-${approval.approval_id}-approve`}
                      disabled={busy || !onApprovalDecision}
                      onClick={() => onApprovalDecision?.(approval.approval_id, "approved")}
                      type="button"
                    >
                      Approve exact plan once
                    </button>
                    <button
                      className="min-h-9 rounded-md border border-[var(--line)] px-3 font-semibold disabled:opacity-50"
                      data-testid={`autopilot-approval-${approval.approval_id}-deny`}
                      disabled={busy || !onApprovalDecision}
                      onClick={() => onApprovalDecision?.(approval.approval_id, "denied")}
                      type="button"
                    >
                      Deny
                    </button>
                  </div>
                )}
              </li>
            );
          })
        )}
      </ul>
    </PanelSection>
  );
}

function SteeringControls({
  branches,
  onSteer,
  busy,
  emergencyStopped,
}: {
  branches: AutopilotBranchProjection[];
  onSteer?: (request: AutopilotSteeringRequest) => void;
  busy?: boolean;
  emergencyStopped: boolean;
}) {
  const [selectedBranchId, setSelectedBranchId] = useState(branches[0]?.branch_id ?? "");
  const [guidance, setGuidance] = useState("");
  const activeSelectedBranchId = branches.some(
    (branch) => branch.branch_id === selectedBranchId,
  )
    ? selectedBranchId
    : branches[0]?.branch_id ?? "";

  const controlsDisabled = Boolean(busy || emergencyStopped || !onSteer);
  return (
    <PanelSection testId="autopilot-steering" title="Steering">
      <p className="mb-3 text-xs text-[var(--muted)]">
        Priority and bounded hypothesis guidance only. Scope, risk, recipes, request templates,
        and budgets remain server-bound.
      </p>
      <ul className="grid gap-2 text-xs text-[var(--muted)]">
        {branches.length === 0 ? (
          <li>No branches to steer</li>
        ) : (
          branches.map((branch) => (
            <li className="flex flex-wrap items-center justify-between gap-2" key={branch.branch_id}>
              <span className="font-mono">{branch.branch_id} · {branch.priority}</span>
              <button
                className="min-h-9 rounded-md border border-[var(--line)] px-3 font-semibold text-[var(--foreground)] disabled:opacity-50"
                data-testid={`autopilot-priority-${branch.branch_id}`}
                disabled={controlsDisabled}
                onClick={() =>
                  onSteer?.({
                    branch_id: branch.branch_id,
                    directive: "set_priority",
                    priority: Math.min(10_000, branch.priority + 10),
                    reason: "operator_priority",
                  })
                }
                type="button"
              >
                Raise priority
              </button>
            </li>
          ))
        )}
      </ul>
      {branches.length > 0 ? (
        <div className="mt-4 grid gap-2">
          <label className="grid gap-1 text-xs">
            <span className="font-semibold text-[var(--foreground)]">Guidance branch</span>
            <select
              className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3"
              data-testid="autopilot-guidance-branch"
              disabled={controlsDisabled}
              onChange={(event) => setSelectedBranchId(event.target.value)}
              value={activeSelectedBranchId}
            >
              {branches.map((branch) => (
                <option key={branch.branch_id} value={branch.branch_id}>
                  {branch.branch_id}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-xs">
            <span className="font-semibold text-[var(--foreground)]">Bounded hypothesis guidance</span>
            <input
              className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3"
              data-testid="autopilot-guidance-input"
              disabled={controlsDisabled}
              maxLength={240}
              onChange={(event) => setGuidance(event.target.value)}
              value={guidance}
            />
          </label>
          <button
            className="min-h-9 justify-self-start rounded-md border border-[var(--line)] px-3 text-xs font-semibold disabled:opacity-50"
            data-testid="autopilot-guidance-submit"
            disabled={controlsDisabled || !activeSelectedBranchId || guidance.trim().length === 0}
            onClick={() => {
              onSteer?.({
                branch_id: activeSelectedBranchId,
                directive: "add_hypothesis_guidance",
                hypothesis_guidance: guidance.trim(),
                reason: "operator_hypothesis_guidance",
              });
              setGuidance("");
            }}
            type="button"
          >
            Add hypothesis guidance
          </button>
        </div>
      ) : null}
    </PanelSection>
  );
}

export function AutopilotPanel({
  projection,
  onEmergencyStop,
  onPrepareEmergencyStop,
  onSteer,
  onApprovalDecision,
  busy,
}: AutopilotPanelProps) {
  const [stopPreparation, setStopPreparation] =
    useState<AutopilotEmergencyStopPreparation | null>(null);
  const summary = summarizeAutopilotProjection(projection);
  const activeStopPreparation = projection.emergency_stopped ? null : stopPreparation;

  return (
    <section
      aria-label="Bounty Autopilot"
      className="border border-[var(--line)] bg-white p-4 text-[var(--foreground)] sm:p-5"
      data-testid="autopilot-panel"
    >
      <header className="mb-4 flex flex-col items-stretch justify-between gap-3 sm:flex-row sm:items-start">
        <div>
          <h2 className="text-lg font-semibold text-[var(--accent-strong)]">Bounty Autopilot</h2>
          <p className="text-sm text-[var(--muted)]" data-testid="autopilot-summary">
            {summary}
          </p>
          <p className="mt-1 text-xs text-[var(--muted)]">
            policy {projection.policy_mode ?? "unknown"} · mode {projection.campaign_mode}
          </p>
        </div>
        <button
          className="min-h-10 rounded-md bg-[var(--danger)] px-4 text-sm font-semibold text-white disabled:opacity-50"
          data-testid="autopilot-emergency-stop"
          disabled={
            projection.emergency_stopped ||
            busy ||
            !onEmergencyStop ||
            !onPrepareEmergencyStop
          }
          onClick={() => {
            void onPrepareEmergencyStop?.().then((prepared) => {
              if (prepared) {
                setStopPreparation(prepared);
              }
            });
          }}
          type="button"
        >
          {projection.emergency_stopped ? "Emergency stopped" : "Emergency Stop"}
        </button>
      </header>

      {activeStopPreparation ? (
        <div
          aria-label="Confirm campaign emergency stop"
          className="mb-4 grid gap-2 border border-[var(--danger)] p-3 text-sm"
          data-testid="autopilot-emergency-stop-confirmation"
          role="alertdialog"
        >
          <p>
            Confirm Campaign-wide stop. The server must revoke active leases before this view
            reports the Campaign stopped.
          </p>
          <p className="text-xs text-[var(--muted)]">
            One-time confirmation expires at {activeStopPreparation.expires_at}.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              className="min-h-9 rounded-md bg-[var(--danger)] px-3 font-semibold text-white disabled:opacity-50"
              data-testid="autopilot-emergency-stop-confirm"
              disabled={busy}
              onClick={() => {
                if (Date.parse(activeStopPreparation.expires_at) <= Date.now()) {
                  setStopPreparation(null);
                  return;
                }
                const confirmationNonce = activeStopPreparation.confirmation_nonce;
                setStopPreparation(null);
                onEmergencyStop?.(confirmationNonce);
              }}
              type="button"
            >
              Confirm emergency stop
            </button>
            <button
              className="min-h-9 rounded-md border border-[var(--line)] px-3 font-semibold disabled:opacity-50"
              data-testid="autopilot-emergency-stop-cancel"
              disabled={busy}
              onClick={() => setStopPreparation(null)}
              type="button"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      <dl className="mb-5 grid grid-cols-2 gap-3 text-xs md:grid-cols-4">
        <SummaryField
          label="Active leases"
          testId="autopilot-active-leases"
          value={projection.budgets.active_leases}
        />
        <SummaryField
          label="Requests used"
          value={`${projection.budgets.campaign_requests_used}/${projection.budgets.campaign_max_requests || "not set"}`}
        />
        <SummaryField label="Open approvals" value={projection.budgets.open_approvals} />
        <SummaryField
          label="Submission"
          testId="autopilot-submission-blocked"
          value={projection.submission_blocked ? "blocked" : "open"}
        />
      </dl>

      <div className="grid gap-5 lg:grid-cols-2">
        <AgentGraph branches={projection.branches} nextBranchId={projection.next_branch_id} />
        <AssetMap assets={projection.assets} />
        <ResearchQueue
          branches={projection.branches}
          nextBranchId={projection.next_branch_id}
          nextReason={projection.next_reason}
        />
        <LiveTimeline events={projection.events} />
        <BudgetMonitor budgets={projection.budgets} />
        <ApprovalInbox
          approvals={projection.approvals}
          busy={busy}
          onApprovalDecision={onApprovalDecision}
        />
        <SteeringControls
          branches={projection.branches}
          busy={busy}
          emergencyStopped={projection.emergency_stopped}
          onSteer={onSteer}
        />
      </div>
    </section>
  );
}

function PanelSection({
  children,
  testId,
  title,
}: {
  children: React.ReactNode;
  testId: string;
  title: string;
}) {
  return (
    <section className="min-w-0 border-t border-[var(--line)] pt-3" data-testid={testId}>
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      {children}
    </section>
  );
}

function SummaryField({
  label,
  testId,
  value,
}: {
  label: string;
  testId?: string;
  value: number | string;
}) {
  return (
    <div>
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="font-mono" data-testid={testId}>{value}</dd>
    </div>
  );
}
