import { FileWarning } from "lucide-react";
import type { ReactNode } from "react";

import type { StudioCandidateCard } from "@/lib/studio-data";
import { formatLabel } from "@/lib/workbench-display";

interface ReportInspectorProps {
  actions?: ReactNode;
  candidate: StudioCandidateCard | null;
  dossierPaths?: string[];
  markdownPath?: string | null;
}

export function ReportInspector({ actions, candidate, dossierPaths = [], markdownPath }: ReportInspectorProps) {
  return (
    <section aria-labelledby="report-inspector-title" className="border-t border-[var(--cc-border)] py-4">
      <div className="flex items-center justify-between gap-3"><div className="flex items-center gap-2"><FileWarning aria-hidden="true" className="size-4 text-[var(--cc-violet)]" /><h3 className="text-sm font-semibold" id="report-inspector-title">报告草稿</h3></div><span className="rounded-sm border border-[var(--cc-warning-border)] px-2 py-1 font-mono text-[10px] text-[var(--cc-warning)]">报告提交已阻断</span></div>
      <dl className="mt-3 grid gap-3 text-xs"><div><dt className="text-[var(--cc-text-muted)]">就绪状态</dt><dd className="mt-1">{formatLabel(candidate?.reportReadiness.status ?? "等待候选审查")}</dd></div><div><dt className="text-[var(--cc-text-muted)]">下一步</dt><dd className="mt-1 leading-5">{candidate?.reportReadiness.nextAllowedAction ?? "完成证据与声明人工审查"}</dd></div>{markdownPath ? <div><dt className="text-[var(--cc-text-muted)]">Markdown 草稿</dt><dd className="mt-1 break-all font-mono">{markdownPath}</dd></div> : null}{dossierPaths.map((path) => <div key={path}><dt className="text-[var(--cc-text-muted)]">任务档案</dt><dd className="mt-1 break-all font-mono">{path}</dd></div>)}</dl>
      {actions ? <div className="mt-4 flex flex-wrap gap-2 border-t border-[var(--cc-border)] pt-4">{actions}</div> : null}
      <p className="mt-3 text-xs leading-5 text-[var(--cc-text-muted)]">仅可预览或显式本地导出；研究工作台不提供自动提交命令。</p>
    </section>
  );
}
