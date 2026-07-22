"use client";

import { Menu, PanelRightOpen, ShieldCheck, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface StudioShellProps {
  candidates: ReactNode;
  children: ReactNode;
  connectionLabel: string;
  inspector: ReactNode;
  navigation: ReactNode;
  safetyLabel: string;
  workspaceName: string;
}

export function StudioShell({
  candidates,
  children,
  connectionLabel,
  inspector,
  navigation,
  safetyLabel,
  workspaceName,
}: StudioShellProps) {
  const [inspectorPlacement, setInspectorPlacement] = useState<
    "mobile" | "drawer" | "desktop" | null
  >(null);

  useEffect(() => {
    const desktop = window.matchMedia("(min-width: 1100px)");
    const tablet = window.matchMedia("(min-width: 640px)");
    const updatePlacement = () => {
      setInspectorPlacement(desktop.matches ? "desktop" : tablet.matches ? "drawer" : "mobile");
    };

    updatePlacement();
    desktop.addEventListener("change", updatePlacement);
    tablet.addEventListener("change", updatePlacement);
    return () => {
      desktop.removeEventListener("change", updatePlacement);
      tablet.removeEventListener("change", updatePlacement);
    };
  }, []);

  return (
    <main className="precision-ops control-center-theme min-h-dvh bg-[var(--cc-bg)] text-[var(--cc-text)] [--cc-accent-soft:var(--accent-surface)] [--cc-accent:var(--accent)] [--cc-bg:var(--background)] [--cc-border-strong:var(--input)] [--cc-border:var(--line)] [--cc-danger:var(--danger)] [--cc-surface-glass:var(--surface-glass)] [--cc-surface-raised:var(--surface-raised)] [--cc-surface:var(--surface)] [--cc-text-muted:var(--muted)] [--cc-text:var(--foreground)] [--cc-violet:var(--advisory)] [--cc-warning-border:#6a5224] [--cc-warning-soft:#2c2415] [--cc-warning:var(--warning)]">
      <a
        className="sr-only rounded-sm bg-[var(--cc-accent)] px-3 py-2 text-white focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50"
        href="#studio-main"
      >
        跳到研究工作区
      </a>
      <header className="sticky top-0 z-30 flex min-h-16 items-center justify-between border-b border-[var(--cc-border)] bg-[color:var(--cc-surface-glass)] px-4 backdrop-blur-xl lg:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid size-9 shrink-0 place-items-center rounded-md border border-[var(--cc-border-strong)] bg-[var(--cc-surface-raised)] text-[var(--cc-accent)]">
            <ShieldCheck aria-hidden="true" className="size-5" />
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold">Mythos Studio</p>
            <p className="truncate text-xs text-[var(--cc-text-muted)]">{workspaceName}</p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="hidden text-[var(--cc-text-muted)] sm:inline">{connectionLabel}</span>
          <span className="rounded-sm border border-[var(--cc-warning-border)] bg-[var(--cc-warning-soft)] px-2 py-1 text-[var(--cc-warning)]">
            {safetyLabel}
          </span>
          {inspectorPlacement === "drawer" ? <Sheet>
            <SheetTrigger asChild>
              <Button
                className="hidden sm:inline-flex min-[1100px]:hidden"
                size="icon-sm"
                title="打开详情检查器"
                variant="outline"
              >
                <PanelRightOpen aria-hidden="true" />
                <span className="sr-only">打开详情检查器</span>
              </Button>
            </SheetTrigger>
            <SheetContent
              aria-label="候选详情抽屉"
              className="w-full max-w-[430px] border-[var(--cc-border-strong)] bg-[var(--cc-surface-glass)] p-0 backdrop-blur-xl"
              id="studio-inspector-drawer"
              showCloseButton={false}
            >
              <SheetHeader className="border-b border-[var(--cc-border)]">
                <SheetTitle>候选详情抽屉</SheetTitle>
                <SheetDescription>证据、验证计划与 submission-blocked 报告审查</SheetDescription>
                <SheetClose asChild>
                  <Button className="absolute right-3 top-3" size="icon-sm" title="关闭详情检查器" variant="ghost">
                    <X aria-hidden="true" />
                    <span className="sr-only">关闭详情检查器</span>
                  </Button>
                </SheetClose>
              </SheetHeader>
              <div className="min-h-0 flex-1 overflow-y-auto p-4">{inspector}</div>
            </SheetContent>
          </Sheet> : null}
        </div>
      </header>

      <Tabs className="!block gap-0" defaultValue="overview">
        <TabsList
          aria-label="Studio 移动视图"
          className="grid h-11 w-full grid-cols-3 rounded-none border-b border-[var(--cc-border)] bg-transparent p-0 sm:hidden"
          variant="line"
        >
          <TabsTrigger className="rounded-none" value="overview">总览</TabsTrigger>
          <TabsTrigger className="rounded-none" value="candidates">候选</TabsTrigger>
          <TabsTrigger className="rounded-none" value="details">详情</TabsTrigger>
        </TabsList>

        <div className="mx-auto grid w-full max-w-[1800px] min-[1100px]:grid-cols-[260px_minmax(0,1fr)_390px]">
          <TabsContent
            className="m-0 min-w-0 data-[state=inactive]:hidden sm:contents"
            forceMount
            tabIndex={-1}
            value="overview"
          >
            <section className="min-w-0 p-4 lg:p-6 min-[1100px]:col-start-2" id="studio-main">
              {children}
            </section>
            <aside
              aria-label="工作区导航"
              className="min-w-0 border-r border-[var(--cc-border)] bg-[var(--cc-surface)] p-4 min-[1100px]:col-start-1 min-[1100px]:row-start-1 min-[1100px]:sticky min-[1100px]:top-16 min-[1100px]:h-[calc(100dvh-4rem)] min-[1100px]:overflow-y-auto"
            >
              <div className="mb-3 flex items-center gap-2 text-xs font-semibold text-[var(--cc-text-muted)]">
                <Menu aria-hidden="true" className="size-4" />
                工作区
              </div>
              {navigation}
            </aside>
          </TabsContent>

          {inspectorPlacement === "desktop" ? <aside
            aria-label="候选检查器"
            className="hidden border-l border-[var(--cc-border)] bg-[var(--cc-surface)] p-4 min-[1100px]:sticky min-[1100px]:top-16 min-[1100px]:block min-[1100px]:h-[calc(100dvh-4rem)] min-[1100px]:overflow-y-auto"
          >
            {inspector}
          </aside> : null}
        </div>

        <TabsContent className="m-0 p-4 data-[state=inactive]:hidden sm:hidden" forceMount tabIndex={-1} value="candidates">
          <section aria-label="候选列表">{candidates}</section>
        </TabsContent>
        <TabsContent className="m-0 p-4 data-[state=inactive]:hidden sm:hidden" forceMount tabIndex={-1} value="details">
          {inspectorPlacement === "mobile" ? <section aria-label="候选详情">{inspector}</section> : null}
        </TabsContent>
      </Tabs>
    </main>
  );
}
