import { Check, Circle, CircleAlert, LoaderCircle } from "lucide-react";

import { SectionHeader } from "@/components/control-center/section-header";
import type { ControlCenterSnapshot } from "@/lib/control-center-data";
import { cn } from "@/lib/utils";

interface AgentPipelineProps {
  stages: ControlCenterSnapshot["agentStages"];
}

export function AgentPipeline({ stages }: AgentPipelineProps) {
  return (
    <section aria-label="Agent 研究流水线" className="border-b border-border py-5">
      <SectionHeader
        title="Agent 研究流水线"
        description="每个阶段都来自持久化审计记录；阻断与等待不会被解释为成功。"
        className="px-4 lg:px-6"
      />
      {stages.length === 0 ? (
        <p className="px-4 py-5 text-sm text-muted-foreground lg:px-6">尚无可追踪的研究阶段。</p>
      ) : (
        <ol className="grid gap-px border-y border-border bg-border sm:grid-cols-2 xl:grid-cols-5">
          {stages.map((stage, index) => {
            const Icon = stage.status === "completed"
              ? Check
              : stage.status === "running"
                ? LoaderCircle
                : stage.status === "blocked"
                  ? CircleAlert
                  : Circle;
            return (
              <li key={stage.key} className="min-w-0 bg-[var(--surface)] px-4 py-4">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[0.6875rem] text-muted-foreground">0{index + 1}</span>
                  <Icon
                    aria-hidden="true"
                    className={cn(
                      "size-4",
                      stage.status === "completed" && "text-safe",
                      stage.status === "running" && "text-primary",
                      stage.status === "blocked" && "text-danger",
                      !["completed", "running", "blocked"].includes(stage.status) && "text-muted-foreground",
                    )}
                  />
                  <p className="truncate text-sm font-semibold">{stage.label}</p>
                </div>
                <div className="mt-3 flex items-center justify-between gap-3 text-xs">
                  <span className="text-muted-foreground">{stage.statusLabel}</span>
                  <span className="font-mono tabular-nums text-foreground">{stage.recordCount} 记录</span>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
