import { FileWarning } from "lucide-react";

import type { StudioCandidateCard } from "@/lib/studio-data";

interface ReportInspectorProps {
  candidate: StudioCandidateCard | null;
  markdownPath?: string | null;
}

export function ReportInspector({ candidate, markdownPath }: ReportInspectorProps) {
  return (
    <section aria-labelledby="report-inspector-title" className="border-t border-[var(--cc-border)] py-4">
      <div className="flex items-center justify-between gap-3"><div className="flex items-center gap-2"><FileWarning aria-hidden="true" className="size-4 text-[var(--cc-violet)]" /><h3 className="text-sm font-semibold" id="report-inspector-title">报告草稿</h3></div><span className="rounded-sm border border-[var(--cc-warning-border)] px-2 py-1 font-mono text-[10px] text-[var(--cc-warning)]">submission-blocked</span></div>
      <dl className="mt-3 grid gap-3 text-xs"><div><dt className="text-[var(--cc-text-muted)]">就绪状态</dt><dd className="mt-1">{candidate?.reportReadiness.status ?? "等待候选审查"}</dd></div><div><dt className="text-[var(--cc-text-muted)]">下一步</dt><dd className="mt-1 leading-5">{candidate?.reportReadiness.nextAllowedAction ?? "完成证据与声明人工审查"}</dd></div>{markdownPath ? <div><dt className="text-[var(--cc-text-muted)]">Markdown draft</dt><dd className="mt-1 break-all font-mono">{markdownPath}</dd></div> : null}</dl>
      <p className="mt-3 text-xs leading-5 text-[var(--cc-text-muted)]">仅可预览或显式本地导出；Studio 不提供自动提交命令。</p>
    </section>
  );
}
