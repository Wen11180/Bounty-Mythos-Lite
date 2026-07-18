import { Activity, Clock3 } from "lucide-react";

import { PanelState } from "@/components/control-center/panel-state";
import { SectionHeader } from "@/components/control-center/section-header";
import type { ControlCenterSnapshot } from "@/lib/control-center-data";

interface AuditEventStreamProps {
  events: ControlCenterSnapshot["recentEvents"];
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "时间待复核";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

export function AuditEventStream({ events }: AuditEventStreamProps) {
  return (
    <section aria-label="净化审计事件" className="border border-border bg-[#070b10]">
      <div className="px-4 pt-4">
        <SectionHeader
          title="净化审计事件"
          description="仅显示状态、稳定标识和时间，不显示原始请求、响应或凭据。"
          actions={<Activity aria-hidden="true" className="size-4 text-safe" />}
        />
      </div>
      {events.length === 0 ? (
        <PanelState state="empty" detail="尚无研究任务或流水线状态事件。" />
      ) : (
        <ol className="divide-y divide-border border-t border-border font-mono text-xs">
          {events.slice(0, 8).map((event) => (
            <li key={event.id} className="grid gap-2 px-4 py-2.5 sm:grid-cols-[5.5rem_7rem_minmax(0,1fr)_8rem] sm:items-center">
              <time dateTime={event.occurredAt} className="flex items-center gap-1.5 text-muted-foreground">
                <Clock3 aria-hidden="true" className="size-3.5" />
                {formatTime(event.occurredAt)}
              </time>
              <span className="text-primary">[{event.typeLabel}]</span>
              <span className="truncate text-foreground">{event.id}</span>
              <span className="text-muted-foreground sm:text-right">{event.statusLabel}</span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
