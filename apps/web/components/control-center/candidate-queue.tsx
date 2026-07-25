import { ArrowUpRight, FileQuestion } from "lucide-react";
import Link from "next/link";

import { PanelState } from "@/components/control-center/panel-state";
import { SectionHeader } from "@/components/control-center/section-header";
import { Badge } from "@/components/ui/badge";
import type { ControlCenterSnapshot } from "@/lib/control-center-data";

interface CandidateQueueProps {
  candidates: ControlCenterSnapshot["candidates"];
}

export function CandidateQueue({ candidates }: CandidateQueueProps) {
  return (
    <section aria-label="候选与验证队列" className="min-w-0 border border-border bg-[var(--surface)]">
      <div className="px-4 pt-4">
        <SectionHeader
          title="候选与验证队列"
          description="候选并非已确认漏洞；验证仍受人工批准和范围守卫约束。"
        />
      </div>
      {candidates.length === 0 ? (
        <PanelState state="empty" detail="完成授权输入分析后，高价值保留候选会出现在这里。" />
      ) : (
        <div className="divide-y divide-border border-t border-border">
          {candidates.slice(0, 5).map((candidate) => (
            <article key={candidate.id} className="grid gap-3 px-4 py-3 sm:grid-cols-[2rem_minmax(0,1fr)_auto] sm:items-center">
              <div className="flex size-8 items-center justify-center rounded-md border border-border bg-muted/35 font-mono text-xs tabular-nums text-primary">
                {candidate.rank}
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="font-semibold">{candidate.vulnerabilityType}</p>
                  <Badge variant="outline" className="border-approval/35 bg-approval/10 text-approval">
                    {candidate.validationLabel}
                  </Badge>
                </div>
                <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{candidate.endpoint}</p>
                <p className="mt-1 flex items-center gap-1.5 truncate text-xs text-muted-foreground">
                  <FileQuestion aria-hidden="true" className="size-3.5 shrink-0" />
                  {candidate.codePath ?? "代码路径待补证"} · {candidate.evidenceLabel}
                </p>
              </div>
              <Link
                href={`/campaigns/${encodeURIComponent(candidate.campaignId)}/hypothesis-board`}
                className="inline-flex min-h-8 items-center justify-center gap-1.5 rounded-md border border-border px-2 text-xs font-medium hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring"
              >
                审查
                <ArrowUpRight aria-hidden="true" className="size-3.5" />
              </Link>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
