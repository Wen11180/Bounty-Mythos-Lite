import { ShieldAlert } from "lucide-react";

import type { StudioCandidateCard } from "@/lib/studio-data";
import { formatLabel } from "@/lib/workbench-display";

export function ValidationPlanInspector({ candidate }: { candidate: StudioCandidateCard | null }) {
  return (
    <section aria-labelledby="validation-plan-title" className="border-t border-[var(--cc-border)] py-4">
      <div className="flex items-center gap-2"><ShieldAlert aria-hidden="true" className="size-4 text-[var(--cc-warning)]" /><h3 className="text-sm font-semibold" id="validation-plan-title">安全验证计划</h3></div>
      <p className="mt-2 text-xs text-[var(--cc-warning)]">人工批准前禁止执行；仅限已授权、非破坏性、限速的本地或隔离流程。</p>
      <p className="mt-2 font-mono text-xs text-[var(--cc-text-muted)]">
        验证模式：{formatLabel(candidate?.validationMode ?? "manual_review")}
      </p>
      <ol className="mt-3 space-y-2 text-xs text-[var(--cc-text-muted)]">
        {(candidate?.safeValidationPlan ?? []).map((step, index) => <li className="grid grid-cols-[20px_minmax(0,1fr)] gap-2" key={`${step}-${index}`}><span className="font-mono">{index + 1}</span><span>{step}</span></li>)}
        {(candidate?.safeValidationPlan.length ?? 0) === 0 ? <li>尚无可审查的安全验证步骤。</li> : null}
      </ol>
      <div className="mt-4 border-t border-[var(--cc-border)] pt-3 text-xs">
        <p className="font-semibold">安全阻断项</p>
        <p className="mt-1 text-[var(--cc-text-muted)]">
          {candidate?.safetyBlockers.join(" · ") || "需要人工审核。"}
        </p>
        <p className="mt-3 font-semibold">候选证据缺口</p>
        <p className="mt-1 text-[var(--cc-text-muted)]">
          {candidate?.evidenceGaps.join(" · ") || "需要审核。"}
        </p>
      </div>
    </section>
  );
}
