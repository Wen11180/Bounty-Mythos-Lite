import type { StudioCandidateCard } from "@/lib/studio-data";

export function EvidenceInspector({ candidate }: { candidate: StudioCandidateCard | null }) {
  const evidence = candidate?.evidenceNeeds ?? [];
  const gaps = candidate?.evidenceGaps ?? [];
  return (
    <section aria-labelledby="evidence-title" className="border-t border-[var(--cc-border)] py-4">
      <div className="flex items-center justify-between gap-3"><h3 className="text-sm font-semibold" id="evidence-title">证据</h3><span className="text-xs text-[var(--cc-text-muted)]">脱敏审查</span></div>
      <p className="mt-2 text-xs leading-5 text-[var(--cc-text-muted)]">只展示来源摘要和证据缺口；原始密钥、令牌、Cookie、授权请求头与用户数据均保持排除。</p>
      <ul className="mt-3 space-y-2 text-xs">
        {[...evidence, ...gaps].slice(0, 6).map((item, index) => <li className="border-l-2 border-[var(--cc-warning)] pl-2 text-[var(--cc-text-muted)]" key={`${item}-${index}`}>{item}</li>)}
        {evidence.length + gaps.length === 0 ? <li className="text-[var(--cc-text-muted)]">暂无可展示证据，仍需人工审查。</li> : null}
      </ul>
      <div className="mt-4 border-t border-[var(--cc-border)] pt-3 text-xs">
        <p className="font-semibold">证据重点</p>
        <p className="mt-1 text-[var(--cc-text-muted)]">
          {candidate?.evidenceFocus.join(" · ") || "需要审核。"}
        </p>
        <p className="mt-3 font-semibold">语义证据</p>
        <p className="mt-1 text-[var(--cc-text-muted)]">
          {candidate?.semanticEvidence.securityInvariant ?? "安全不变量需要审核。"}
        </p>
      </div>
    </section>
  );
}
