import { Check, Circle, ShieldAlert } from "lucide-react";

import { cn } from "@/lib/utils";

interface MissionStageStripProps {
  activeStage: string;
  stages: Array<{ key: string; label: string; status: string; summary: string }>;
}

export function MissionStageStrip({ activeStage, stages }: MissionStageStripProps) {
  return (
    <section aria-labelledby="mission-stage-title" className="border-y border-[var(--cc-border)] py-3">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold" id="mission-stage-title">研究阶段</h2>
        <span className="font-mono text-xs text-[var(--cc-text-muted)]">review-only</span>
      </div>
      <ol className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {stages.map((stage, index) => {
          const blocked = /block|stop|unsafe/i.test(stage.status);
          const complete = /complete|done|passed|ready/i.test(stage.status);
          const active = stage.key === activeStage || (!activeStage && index === 0);
          const Icon = blocked ? ShieldAlert : complete ? Check : Circle;
          return (
            <li
              className={cn(
                "min-w-0 border-l-2 border-[var(--cc-border-strong)] px-3 py-1.5",
                active && "border-[var(--cc-accent)] bg-[var(--cc-accent-soft)]",
                blocked && "border-[var(--cc-danger)]",
              )}
              key={stage.key}
              title={stage.summary}
            >
              <div className="flex items-center gap-2">
                <Icon aria-hidden="true" className="size-3.5 shrink-0" />
                <span className="truncate text-xs font-semibold">{stage.label}</span>
              </div>
              <p className="mt-1 truncate text-[11px] text-[var(--cc-text-muted)]">{stage.status}</p>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
