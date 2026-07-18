"use client";

import { PanelRightOpen } from "lucide-react";
import { useSyncExternalStore, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

interface ResponsiveInspectorProps {
  children: ReactNode;
  title: string;
  description?: string;
  trigger?: ReactNode;
  className?: string;
}

const desktopQuery = "(min-width: 1100px)";

function subscribeToDesktopQuery(onStoreChange: () => void) {
  const mediaQuery = window.matchMedia(desktopQuery);
  mediaQuery.addEventListener("change", onStoreChange);
  return () => mediaQuery.removeEventListener("change", onStoreChange);
}

function getDesktopSnapshot() {
  return window.matchMedia(desktopQuery).matches;
}

function getServerDesktopSnapshot() {
  return false;
}

export function ResponsiveInspector({
  children,
  title,
  description,
  trigger,
  className,
}: ResponsiveInspectorProps) {
  const isDesktop = useSyncExternalStore(
    subscribeToDesktopQuery,
    getDesktopSnapshot,
    getServerDesktopSnapshot,
  );

  const inspectorContent = <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>;

  if (isDesktop) {
    return (
      <aside aria-label={title} className={cn("min-w-0 border-l border-border", className)}>
        {inspectorContent}
      </aside>
    );
  }

  return (
    <Sheet>
      {trigger ? (
        <SheetTrigger asChild>{trigger}</SheetTrigger>
      ) : (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <SheetTrigger asChild>
                <Button variant="outline" size="icon" aria-label="打开详情">
                  <PanelRightOpen aria-hidden="true" />
                </Button>
              </SheetTrigger>
            </TooltipTrigger>
            <TooltipContent>打开详情</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )}
      <SheetContent className="w-[min(92vw,30rem)] border-border bg-[var(--surface-glass)] backdrop-blur-md">
        <SheetHeader className="border-b border-border">
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>{description ?? "研究详情检查器"}</SheetDescription>
        </SheetHeader>
        {inspectorContent}
      </SheetContent>
    </Sheet>
  );
}
