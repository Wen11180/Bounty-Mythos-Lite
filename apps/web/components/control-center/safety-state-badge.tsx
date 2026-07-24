import { ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  safetyStateDisplay,
  statusToneClassName,
  type UnsafeSafetyState,
} from "@/lib/control-center-display";
import { cn } from "@/lib/utils";

interface SafetyStateBadgeProps {
  state: UnsafeSafetyState;
  className?: string;
}

export function SafetyStateBadge({ state, className }: SafetyStateBadgeProps) {
  const display = safetyStateDisplay(state);

  return (
    <Badge
      variant="outline"
      className={cn("gap-1.5 whitespace-nowrap", statusToneClassName(display.tone), className)}
    >
      <ShieldAlert aria-hidden="true" className="size-3" />
      {display.label}
    </Badge>
  );
}
