import { CircleAlert, CloudOff, Clock3, Inbox } from "lucide-react";
import type { ReactNode } from "react";

import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export type PanelStateKind = "empty" | "loading" | "error" | "stale" | "offline";

interface PanelStateProps {
  state: PanelStateKind;
  title?: string;
  detail?: ReactNode;
  action?: ReactNode;
  className?: string;
}

const defaults: Record<
  Exclude<PanelStateKind, "loading">,
  { title: string; icon: typeof Inbox }
> = {
  empty: { title: "暂无可显示数据", icon: Inbox },
  error: { title: "数据读取失败", icon: CircleAlert },
  stale: { title: "当前快照已过期", icon: Clock3 },
  offline: { title: "当前连接离线", icon: CloudOff },
};

export function PanelState({ state, title, detail, action, className }: PanelStateProps) {
  if (state === "loading") {
    return (
      <div
        role="status"
        aria-live="polite"
        aria-busy="true"
        aria-label={title ?? "正在加载"}
        className={cn("grid min-h-32 gap-3 p-5", className)}
      >
        <Skeleton className="h-4 w-32 motion-reduce:animate-none" />
        <Skeleton className="h-8 w-48 motion-reduce:animate-none" />
        <Skeleton className="h-4 w-full max-w-sm motion-reduce:animate-none" />
      </div>
    );
  }

  const { title: defaultTitle, icon: Icon } = defaults[state];

  return (
    <div
      role={state === "error" || state === "offline" ? "alert" : "status"}
      className={cn("flex min-h-32 flex-col items-center justify-center px-5 py-8 text-center", className)}
    >
      <Icon aria-hidden="true" className="size-5 text-muted-foreground" />
      <p className="mt-3 text-sm font-medium">{title ?? defaultTitle}</p>
      {detail ? <div className="mt-1 max-w-md text-xs leading-5 text-muted-foreground">{detail}</div> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
