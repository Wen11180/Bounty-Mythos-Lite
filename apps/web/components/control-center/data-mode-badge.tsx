import { CircleDot } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { dataModeDisplay, statusToneClassName, type DataMode } from "@/lib/control-center-display";

interface DataModeBadgeProps {
  mode: DataMode;
  className?: string;
}

export function DataModeBadge({ mode, className }: DataModeBadgeProps) {
  const display = dataModeDisplay(mode);

  return (
    <Badge
      variant="outline"
      className={cn("gap-1.5 whitespace-nowrap", statusToneClassName(display.tone), className)}
    >
      <CircleDot aria-hidden="true" className="size-3" />
      {display.label}
    </Badge>
  );
}
