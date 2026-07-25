import type { ReactNode } from "react";

import type { StudioCandidateCard } from "@/lib/studio-data";
import { formatLabel } from "@/lib/workbench-display";

interface CandidateInspectorProps {
  actions?: ReactNode;
  candidate: StudioCandidateCard | null;
  candidates: StudioCandidateCard[];
  onSelect(candidateId: string): void;
}

export function CandidateInspector({ actions, candidate, candidates, onSelect }: CandidateInspectorProps) {
  return (
    <section aria-labelledby="candidate-inspector-title">
      <label className="grid gap-2 text-xs font-semibold text-[var(--cc-text-muted)]">
        候选漏洞
        <select
          className="min-h-10 rounded-sm border border-[var(--cc-border-strong)] bg-[var(--cc-surface-raised)] px-3 text-sm text-[var(--cc-text)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--cc-accent)]"
          onChange={(event) => onSelect(event.target.value)}
          value={candidate?.id ?? ""}
        >
          {candidates.length === 0 ? <option value="">暂无候选</option> : null}
          {candidates.map((item) => <option key={item.id} value={item.id}>{item.id} · {item.title}</option>)}
        </select>
      </label>
      <div className="mt-4 border-b border-[var(--cc-border)] pb-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="font-mono text-xs text-[var(--cc-text-muted)]">{candidate?.id ?? "暂无候选"}</p>
            <h2 className="mt-1 text-base font-semibold" id="candidate-inspector-title">{candidate?.title ?? "等待候选"}</h2>
          </div>
          <span className="rounded-sm border border-[var(--cc-warning-border)] bg-[var(--cc-warning-soft)] px-2 py-1 text-xs text-[var(--cc-warning)]">{formatLabel(candidate?.status ?? "review-only")}</span>
        </div>
        <p className="mt-3 text-sm leading-6 text-[var(--cc-text-muted)]">{candidate?.reason ?? "导入授权材料并运行研究后，候选会出现在这里。"}</p>
        <p className="mt-3 text-xs text-[var(--cc-text-muted)]">失效的安全不变量</p>
        <p className="mt-1 text-sm leading-6">{candidate?.brokenInvariant ?? "安全不变量需要审核。"}</p>
      </div>
      <dl className="grid gap-3 py-4 text-sm">
        <div><dt className="text-xs text-[var(--cc-text-muted)]">受影响端点</dt><dd className="mt-1 break-all font-mono text-xs">{candidate?.affectedEndpoint ?? "待补充受影响端点"}</dd></div>
        <div><dt className="text-xs text-[var(--cc-text-muted)]">代码路径</dt><dd className="mt-1 break-all font-mono text-xs">{candidate?.affectedCodePath ?? "待补充代码路径"}</dd></div>
        <div className="grid grid-cols-2 gap-3"><div><dt className="text-xs text-[var(--cc-text-muted)]">风险</dt><dd className="mt-1">{candidate?.severity ?? "待审查"}</dd></div><div><dt className="text-xs text-[var(--cc-text-muted)]">优先级</dt><dd className="mt-1 font-mono">{candidate?.priorityScore ?? 0}</dd></div></div>
      </dl>
      <div className="grid gap-3 border-t border-[var(--cc-border)] py-4 text-xs">
        <div>
          <p className="font-semibold">保留原因</p>
          <p className="mt-1 text-[var(--cc-text-muted)]">
            {candidate?.whyStillAlive.join(" · ") || "需要审核。"}
          </p>
        </div>
        <div>
          <p className="font-semibold">排序原因</p>
          <p className="mt-1 text-[var(--cc-text-muted)]">
            {candidate?.rankingReasons.join(" · ") || "需要审核。"}
          </p>
        </div>
        <div>
          <p className="font-semibold">待反证维度</p>
          <p className="mt-1 text-[var(--cc-text-muted)]">
            {candidate?.falsificationSummary.openDimensions.join(" · ") || "需要审核。"}
          </p>
        </div>
      </div>
      {actions ? <div className="flex flex-wrap gap-2 border-t border-[var(--cc-border)] pt-4">{actions}</div> : null}
    </section>
  );
}
