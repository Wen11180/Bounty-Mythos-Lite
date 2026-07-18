"use client";

import {
  Activity,
  Archive,
  Bot,
  ClipboardCheck,
  FileLock2,
  FileSearch,
  Gauge,
  Home,
  RefreshCw,
  ShieldCheck,
  Target,
} from "lucide-react";
import dynamic from "next/dynamic";
import { useEffect, useState } from "react";

import { AgentPipeline } from "@/components/control-center/agent-pipeline";
import { AppShell, type AppShellNavigationItem } from "@/components/control-center/app-shell";
import { AuditEventStream } from "@/components/control-center/audit-event-stream";
import { AuthorizedAssets } from "@/components/control-center/authorized-assets";
import { CandidateQueue } from "@/components/control-center/candidate-queue";
import { CommandBar } from "@/components/control-center/command-bar";
import { DataModeBadge } from "@/components/control-center/data-mode-badge";
import { Metric } from "@/components/control-center/metric";
import { PanelState } from "@/components/control-center/panel-state";
import { ReportReadiness } from "@/components/control-center/report-readiness";
import { Button } from "@/components/ui/button";
import {
  CONTROL_CENTER_STALE_AFTER_MS,
  isControlCenterSnapshotStale,
  resolveControlCenterDataMode,
  type ControlCenterSnapshot,
} from "@/lib/control-center-data";

const QualityCharts = dynamic(
  () => import("./quality-charts").then((module) => module.QualityCharts),
  {
    ssr: false,
    loading: () => <PanelState state="loading" className="min-h-[26rem] border border-border" title="正在加载研究质量" />,
  },
);

interface ControlCenterOverviewProps {
  initialSnapshot: ControlCenterSnapshot;
}

function navigationFor(snapshot: ControlCenterSnapshot): AppShellNavigationItem[] {
  const navigation: AppShellNavigationItem[] = [
    { href: "/", label: "总览", icon: Home, active: true },
    { href: "/campaigns", label: "授权项目", icon: ShieldCheck },
    { href: "/artifacts", label: "授权资料", icon: Archive },
    { href: "/source-audit", label: "本地代码审计", icon: FileSearch },
    { href: "/studio", label: "研究 Studio", icon: Bot },
  ];
  const campaign = snapshot.campaigns[0];
  if (!campaign) {
    return navigation;
  }
  const root = `/campaigns/${encodeURIComponent(campaign.id)}`;
  navigation.splice(2, 0,
    { href: `${root}/tasks`, label: "研究任务", icon: Activity },
    { href: `${root}/hypothesis-board`, label: "漏洞候选", icon: Target },
    { href: `${root}/validation-queue`, label: "验证批准", icon: ClipboardCheck },
    { href: `${root}/report-drafts`, label: "报告草稿", icon: FileLock2 },
    { href: `${root}/timeline`, label: "审计日志", icon: Gauge },
    { href: `${root}/validation-runs`, label: "Scope Guard", icon: ShieldCheck },
  );
  return navigation;
}

function formatSnapshotTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.getTime() === 0) {
    return "未取得实时快照";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

export function ControlCenterOverview({ initialSnapshot }: ControlCenterOverviewProps) {
  const [isStale, setIsStale] = useState(initialSnapshot.stale);
  useEffect(() => {
    if (initialSnapshot.dataMode !== "live") {
      return;
    }
    const updateStaleState = () =>
      setIsStale(isControlCenterSnapshotStale(initialSnapshot.generatedAt));
    updateStaleState();
    const generatedAtMs = Date.parse(initialSnapshot.generatedAt);
    const delay = Number.isFinite(generatedAtMs)
      ? Math.max(generatedAtMs + CONTROL_CENTER_STALE_AFTER_MS + 1 - Date.now(), 0)
      : 0;
    const timer = window.setTimeout(updateStaleState, delay);
    return () => window.clearTimeout(timer);
  }, [initialSnapshot.dataMode, initialSnapshot.generatedAt]);

  const snapshot = { ...initialSnapshot, stale: isStale };
  const activeCampaign = snapshot.campaigns[0];

  return (
    <AppShell
      navigation={navigationFor(snapshot)}
      productName="Bounty Mythos-Lite"
      productDescription="授权漏洞研究控制中心"
      footer={
        activeCampaign ? (
          <div className="min-w-0">
            <p className="truncate text-xs font-medium">{activeCampaign.name}</p>
            <p className="mt-1 truncate font-mono text-[0.6875rem] text-muted-foreground">{activeCampaign.status}</p>
          </div>
        ) : (
          <p className="text-xs leading-5 text-muted-foreground">Campaign 工作区导航已禁用，请先选择授权项目。</p>
        )
      }
      commandBar={
        <CommandBar
          action="/"
          defaultValue={snapshot.searchQuery}
          label="搜索授权项目、候选、端点或报告"
          placeholder="搜索项目、候选、端点、代码路径或报告"
          actions={
            <>
              <DataModeBadge mode={resolveControlCenterDataMode(snapshot.dataMode, isStale)} />
              <Button
                type="button"
                variant="outline"
                size="icon"
                aria-label="刷新控制中心"
                title="刷新控制中心"
                onClick={() => window.location.reload()}
              >
                <RefreshCw aria-hidden="true" />
              </Button>
            </>
          }
        />
      }
    >
      <div className="mx-auto w-full max-w-[112rem]">
        <header className="border-b border-border px-4 py-5 lg:px-6">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="min-w-0">
              <p className="flex items-center gap-2 text-xs font-medium text-primary">
                <ShieldCheck aria-hidden="true" className="size-4" />
                授权研究态势 · Scope Guard 优先
              </p>
              <h1 className="mt-2 text-2xl font-semibold">Bounty Mythos-Lite 控制中心</h1>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
                汇总授权输入、研究任务、候选反证、人工批准和 submission-blocked 报告草稿。
              </p>
            </div>
            <dl className="grid min-w-64 grid-cols-2 gap-x-4 gap-y-2 text-xs">
              <dt className="text-muted-foreground">快照时间</dt>
              <dd className="text-right font-mono">{formatSnapshotTime(snapshot.generatedAt)}</dd>
              <dt className="text-muted-foreground">Campaign</dt>
              <dd className="truncate text-right">{activeCampaign?.name ?? "未选择"}</dd>
            </dl>
          </div>
        </header>

        {snapshot.searchQuery ? (
          <p className="border-b border-border bg-primary/5 px-4 py-2 text-xs text-muted-foreground lg:px-6">
            列表已按“{snapshot.searchQuery}”筛选；运行指标仍为全局口径。
          </p>
        ) : null}

        {snapshot.error ? (
          <PanelState
            state="error"
            title="无法读取实时控制中心"
            detail={`${snapshot.error}。系统没有回退到演示数据。`}
            className="border-b border-border"
          />
        ) : null}
        {!snapshot.error && isStale ? (
          <PanelState
            state="stale"
            title="显示的是过期快照"
            detail={`最近安全快照生成于 ${formatSnapshotTime(snapshot.generatedAt)}，请刷新后再处理需要新鲜批准状态的操作。`}
            className="min-h-24 border-b border-border"
          />
        ) : null}

        <section aria-label="运行指标" className="grid border-b border-border bg-[var(--surface)] sm:grid-cols-2 xl:grid-cols-4">
          <Metric
            label="运行中的研究任务"
            value={snapshot.metrics.runningTasks ?? undefined}
            detail="持久化任务状态"
            className="px-4 sm:border-r sm:border-border lg:px-6"
          />
          <Metric
            label="高价值保留候选"
            value={snapshot.metrics.retainedCandidates ?? undefined}
            detail="仍需反证与人工复核"
            className="border-t border-border px-4 sm:border-t-0 xl:border-r lg:px-6"
          />
          <Metric
            label="等待人工批准"
            value={snapshot.metrics.approvalPressure ?? undefined}
            detail="未过期审批请求"
            valueClassName="text-approval"
            className="border-t border-border px-4 sm:border-r xl:border-t-0 sm:border-border lg:px-6"
          />
          <Metric
            label="安全与政策阻断"
            value={snapshot.metrics.safetyBlocks ?? undefined}
            detail="Scope Guard 与安全门"
            valueClassName="text-danger"
            className="border-t border-border px-4 xl:border-t-0 lg:px-6"
          />
        </section>

        <AgentPipeline stages={snapshot.agentStages} />

        {snapshot.empty && !snapshot.error ? (
          <PanelState
            state="empty"
            title="控制中心尚无授权研究记录"
            detail="先创建 Campaign，并摄入政策、Scope Guard 规则、API / HAR 或授权本地代码。"
            className="border-b border-border"
          />
        ) : null}

        <div className="grid gap-4 p-4 2xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] lg:p-6">
          <AuthorizedAssets assets={snapshot.authorizedAssets} />
          <CandidateQueue candidates={snapshot.candidates} />
          <QualityCharts quality={snapshot.quality} />
          <ReportReadiness report={snapshot.report} />
          <div className="2xl:col-span-2">
            <AuditEventStream events={snapshot.recentEvents} />
          </div>
        </div>
      </div>
    </AppShell>
  );
}
