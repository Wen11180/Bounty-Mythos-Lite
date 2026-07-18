import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

interface MetricProps {
  label: string;
  value?: ReactNode;
  detail?: ReactNode;
  className?: string;
  valueClassName?: string;
}

export function Metric({ label, value, detail, className, valueClassName }: MetricProps) {
  return (
    <dl className={cn("min-h-20 min-w-0 py-3", className)}>
      <dt className="truncate text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className={cn("mt-1 truncate text-2xl font-semibold tabular-nums", valueClassName)}>
        {value ?? "暂无数据"}
      </dd>
      {detail ? <dd className="mt-1 text-xs text-muted-foreground">{detail}</dd> : null}
    </dl>
  );
}
