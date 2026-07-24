import { ArrowUpRight, FileLock2, ShieldAlert } from "lucide-react";
import Link from "next/link";

import { PanelState } from "@/components/control-center/panel-state";
import { SectionHeader } from "@/components/control-center/section-header";
import { Badge } from "@/components/ui/badge";
import type { ControlCenterSnapshot } from "@/lib/control-center-data";

interface ReportReadinessProps {
  report: ControlCenterSnapshot["report"];
}

export function ReportReadiness({ report }: ReportReadinessProps) {
  return (
    <section aria-label="报告草稿就绪度" className="min-w-0 border border-border bg-[var(--surface)]">
      <div className="px-4 pt-4">
        <SectionHeader
          title="报告草稿就绪度"
          description="报告只提供预览和人工复核，系统不提供自动提交。"
          actions={<Badge variant="outline" className="border-approval/35 bg-approval/10 text-approval">submission-blocked</Badge>}
        />
      </div>
      {!report.available ? (
        <PanelState state="empty" detail="候选完成证据与声明复核后，submission-blocked 草稿会显示在这里。" />
      ) : (
        <div className="border-t border-border px-4 py-4">
          <div className="flex items-start gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md border border-advisory/35 bg-advisory/10 text-advisory">
              <FileLock2 aria-hidden="true" className="size-4" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-semibold">{report.title ?? "未命名报告草稿"}</p>
              <p className="mt-1 text-xs text-muted-foreground">{report.statusLabel} · submission-blocked</p>
            </div>
          </div>
          <dl className="mt-4 grid grid-cols-2 border-y border-border text-sm">
            <div className="py-3 pr-3">
              <dt className="text-xs text-muted-foreground">声明</dt>
              <dd className="mt-1 font-mono tabular-nums">{report.claimCount ?? "暂无数据"}</dd>
            </div>
            <div className="border-l border-border py-3 pl-3">
              <dt className="text-xs text-muted-foreground">证据引用</dt>
              <dd className="mt-1 font-mono tabular-nums">{report.evidenceRefCount ?? "暂无数据"}</dd>
            </div>
          </dl>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
            <p className="flex items-center gap-2 text-xs text-approval">
              <ShieldAlert aria-hidden="true" className="size-4" />
              必须经过证据与声明人工复核
            </p>
            {report.pipelineRunId ? (
              <Link
                href={`/reports/${encodeURIComponent(report.pipelineRunId)}`}
                className="inline-flex min-h-8 items-center gap-1.5 rounded-md border border-border px-2 text-xs font-medium hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring"
              >
                预览草稿
                <ArrowUpRight aria-hidden="true" className="size-3.5" />
              </Link>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}
