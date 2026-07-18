import { Search } from "lucide-react";
import type { ReactNode } from "react";

import { Input } from "@/components/ui/input";

interface CommandBarProps {
  action?: string;
  actions?: ReactNode;
  defaultValue?: string;
  label: string;
  placeholder?: string;
  shortcut?: string;
}

export function CommandBar({
  action,
  actions,
  defaultValue,
  label,
  placeholder,
  shortcut,
}: CommandBarProps) {
  return (
    <div className="flex min-h-14 items-center gap-3 px-4 lg:px-6">
      <form action={action} role="search" className="min-w-0 flex-1">
        <label className="relative block max-w-2xl">
          <span className="sr-only">{label}</span>
          <Search
            aria-hidden="true"
            className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
          />
          <Input
            aria-label={label}
            name="q"
            defaultValue={defaultValue}
            placeholder={placeholder}
            className="h-9 border-border bg-background/75 pl-9 pr-14"
          />
          {shortcut ? (
            <kbd className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 font-mono text-[0.6875rem] text-muted-foreground">
              {shortcut}
            </kbd>
          ) : null}
        </label>
      </form>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  );
}
