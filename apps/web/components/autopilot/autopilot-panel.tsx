"use client";

import {
  budgetMonitorRows,
  canDecideAutopilotApproval,
  classifyAutopilotAssetStatus,
  formatAutopilotLabel,
  orderAutopilotTimeline,
  summarizeAutopilotProjection,
  formatAutopilotDataState,
  type AutopilotDataState,
  type AutopilotCampaignProjection,
} from "@/lib/autopilot-data";

type AutopilotPanelProps = {
  projection: AutopilotCampaignProjection;
  onEmergencyStop?: () => void;
  onSteer?: (branchId: string, priority: number, guidance: string) => void;
  onApprovalDecision?: (
    approvalId: string,
    decision: "approved" | "denied",
  ) => void;
  busy?: boolean;
  dataState?: AutopilotDataState;
};

function AgentGraph({
  branches,
  nextBranchId,
}: {
  branches: Array<Record<string, unknown>>;
  nextBranchId: string | null;
}) {
  return (
    <section data-testid="autopilot-agent-graph">
      <h3 className="mb-1 text-xs font-semibold text-slate-300">智能体分支</h3>
      <ul className="space-y-1 text-xs text-slate-400">
        {branches.length === 0 ? (
          <li>暂无专项分支</li>
        ) : (
          branches.map((branch) => {
            const id = String(branch.branch_id ?? "");
            return (
              <li key={id}>
                {id} · {formatAutopilotLabel(branch.status)}
                {id === nextBranchId ? " · 下一步" : ""}
                {branch.risk_tier ? ` · ${String(branch.risk_tier)}` : ""}
              </li>
            );
          })
        )}
      </ul>
    </section>
  );
}

function AssetMap({ assets }: { assets: Array<Record<string, unknown>> }) {
  return (
    <section data-testid="autopilot-asset-map">
      <h3 className="mb-1 text-xs font-semibold text-slate-300">资产映射</h3>
      <ul className="space-y-1 text-xs text-slate-400">
        {assets.length === 0 ? (
          <li>暂无资产</li>
        ) : (
          assets.map((asset) => {
            const id = String(asset.asset_id ?? "");
            const status = classifyAutopilotAssetStatus(asset.status);
            return (
              <li key={id}>
                {id} · {formatAutopilotLabel(status)}
                {asset.host ? ` · ${String(asset.host)}` : ""}
              </li>
            );
          })
        )}
      </ul>
    </section>
  );
}

function LiveTimeline({ events }: { events: Array<Record<string, unknown>> }) {
  const ordered = orderAutopilotTimeline(events);
  return (
    <section data-testid="autopilot-live-timeline">
      <h3 className="mb-1 text-xs font-semibold text-slate-300">实时时间线</h3>
      <ol className="space-y-1 text-xs text-slate-400">
        {ordered.length === 0 ? (
          <li>暂无事件</li>
        ) : (
          ordered.map((event) => (
            <li key={String(event.event_id)}>
              {formatAutopilotLabel(event.kind)} · {String(event.summary ?? "")}
            </li>
          ))
        )}
      </ol>
    </section>
  );
}

function BudgetMonitor({
  budgets,
}: {
  budgets: AutopilotCampaignProjection["budgets"];
}) {
  return (
    <section data-testid="autopilot-budget-monitor">
      <h3 className="mb-1 text-xs font-semibold text-slate-300">预算监控</h3>
      <dl className="grid grid-cols-1 gap-1 text-xs text-slate-400 sm:grid-cols-2">
        {budgetMonitorRows(budgets).map((row) => (
          <div key={row.label}>
            <dt className="text-slate-500">{row.label}</dt>
            <dd>{row.value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function ApprovalInbox({
  approvals,
  onApprovalDecision,
  busy,
}: {
  approvals: Array<Record<string, unknown>>;
  onApprovalDecision?: (
    approvalId: string,
    decision: "approved" | "denied",
  ) => void;
  busy?: boolean;
}) {
  return (
    <section data-testid="autopilot-approval-inbox">
      <h3 className="mb-1 text-xs font-semibold text-slate-300">审批收件箱</h3>
      <ul className="space-y-2 text-xs text-slate-400">
        {approvals.length === 0 ? (
          <li>暂无待处理审批</li>
        ) : (
          approvals.map((approval) => {
            const id = String(approval.approval_id ?? "");
            const decision = canDecideAutopilotApproval(approval);
            const diff =
              typeof approval.approval_diff === "object" &&
              approval.approval_diff !== null
                ? (approval.approval_diff as Record<string, unknown>)
                : null;
            const methods = Array.isArray(diff?.methods)
              ? diff.methods.map(String).join(", ")
              : "";
            return (
              <li
                key={id}
                className="rounded border border-slate-800 p-2"
                data-testid={`autopilot-approval-${id}`}
              >
                <div>
                  {id} · {formatAutopilotLabel(approval.status)}
                  {approval.risk_tier ? ` · ${String(approval.risk_tier)}` : ""}
                </div>
                {approval.plan_digest ? (
                  <div className="truncate text-[10px] text-slate-500">
                    计划摘要 {String(approval.plan_digest)}
                  </div>
                ) : null}
                {diff?.destination_host ? (
                  <div className="truncate text-[10px] text-slate-500">
                    目标 {String(diff.destination_host)}
                    {diff.destination_path ? String(diff.destination_path) : ""}
                    {methods ? ` · ${methods}` : ""}
                  </div>
                ) : null}
                {!decision.allowed ? (
                  <div className="text-[10px] text-amber-500">{decision.reason}</div>
                ) : (
                  <div className="mt-1 flex gap-2">
                    <button
                      type="button"
                      className="rounded bg-emerald-800 px-2 py-1 text-[10px] text-white disabled:opacity-50"
                      disabled={busy}
                      onClick={() => onApprovalDecision?.(id, "approved")}
                    >
                      批准此计划
                    </button>
                    <button
                      type="button"
                      className="rounded bg-slate-700 px-2 py-1 text-[10px] text-white disabled:opacity-50"
                      disabled={busy}
                      onClick={() => onApprovalDecision?.(id, "denied")}
                    >
                      拒绝
                    </button>
                  </div>
                )}
              </li>
            );
          })
        )}
      </ul>
    </section>
  );
}

function SteeringControls({
  branches,
  onSteer,
  busy,
  emergencyStopped,
}: {
  branches: Array<Record<string, unknown>>;
  onSteer?: (branchId: string, priority: number, guidance: string) => void;
  busy?: boolean;
  emergencyStopped: boolean;
}) {
  return (
    <section data-testid="autopilot-steering">
      <h3 className="mb-1 text-xs font-semibold text-slate-300">研究引导</h3>
      <p className="mb-2 text-[10px] text-slate-500">
        仅支持调整优先级和有限的假设引导；范围、风险、配方和预算仍由服务端控制。
      </p>
      <ul className="space-y-2 text-xs text-slate-400">
        {branches.length === 0 ? (
          <li>暂无可引导分支</li>
        ) : (
          branches.map((branch) => {
            const id = String(branch.branch_id ?? "");
            const priority = Number(branch.priority ?? 0);
            return (
              <li key={id} className="flex flex-wrap items-center gap-2">
                <span className="min-w-28">{id}</span>
                <button
                  type="button"
                  className="rounded border border-slate-700 px-2 py-1 text-[10px] disabled:opacity-50"
                  disabled={busy || emergencyStopped || !onSteer}
                  onClick={() => onSteer?.(id, priority + 10, "raise_priority")}
                >
                  提高优先级
                </button>
              </li>
            );
          })
        )}
      </ul>
    </section>
  );
}

export function AutopilotPanel({
  projection,
  onEmergencyStop,
  onSteer,
  onApprovalDecision,
  busy,
  dataState = "live",
}: AutopilotPanelProps) {
  const summary = summarizeAutopilotProjection(projection);
  const controlsDisabled = dataState !== "live";
  return (
    <section
      aria-label="漏洞赏金自动驾驶"
      className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-slate-100"
      data-testid="autopilot-panel"
    >
      <header className="mb-3 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-cyan-300">
            漏洞赏金自动驾驶
          </h2>
          <p className="text-xs text-slate-400" data-testid="autopilot-summary">
            {summary}
          </p>
          <p className="text-[10px] text-slate-500">
            策略 {formatAutopilotLabel(projection.policy_mode)} · 模式 {formatAutopilotLabel(projection.campaign_mode)}
          </p>
          <p
            className={dataState === "live" ? "text-[10px] text-emerald-400" : "text-[10px] text-amber-400"}
            data-testid="autopilot-data-state"
          >
            {formatAutopilotDataState(dataState)}
          </p>
        </div>
        <button
          type="button"
          className="rounded-md bg-rose-700 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
          data-testid="autopilot-emergency-stop"
          disabled={projection.emergency_stopped || busy}
          onClick={onEmergencyStop}
        >
          紧急停止
        </button>
      </header>
      <dl className="mb-3 grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
        <div>
          <dt className="text-slate-500">生效租约</dt>
          <dd data-testid="autopilot-active-leases">
            {projection.budgets.active_leases}
          </dd>
        </div>
        <div>
          <dt className="text-slate-500">已用请求</dt>
          <dd>
            {projection.budgets.campaign_requests_used}/
            {projection.budgets.campaign_max_requests || "∞"}
          </dd>
        </div>
        <div>
          <dt className="text-slate-500">待审批项</dt>
          <dd>{projection.budgets.open_approvals}</dd>
        </div>
        <div>
          <dt className="text-slate-500">报告提交</dt>
          <dd data-testid="autopilot-submission-blocked">
            {projection.submission_blocked ? "已阻断" : "可提交"}
          </dd>
        </div>
      </dl>
      <div className="grid gap-3 md:grid-cols-2">
        <AgentGraph
          branches={projection.branches}
          nextBranchId={projection.next_branch_id}
        />
        <AssetMap assets={projection.assets} />
        <LiveTimeline events={projection.events} />
        <BudgetMonitor budgets={projection.budgets} />
          <ApprovalInbox
            approvals={projection.approvals}
            onApprovalDecision={onApprovalDecision}
            busy={busy || controlsDisabled}
          />
        <SteeringControls
          branches={projection.branches}
          onSteer={onSteer}
          busy={busy || controlsDisabled}
          emergencyStopped={projection.emergency_stopped}
        />
      </div>
    </section>
  );
}
