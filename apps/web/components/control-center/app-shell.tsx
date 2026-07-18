import { Menu, type LucideIcon } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

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
import { cn } from "@/lib/utils";

export interface AppShellNavigationItem {
  href: string;
  label: string;
  icon: LucideIcon;
  active?: boolean;
  badge?: ReactNode;
}

interface AppShellProps {
  children: ReactNode;
  navigation: AppShellNavigationItem[];
  commandBar?: ReactNode;
  footer?: ReactNode;
  productName?: string;
  productDescription?: string;
}

export function AppShell({
  children,
  navigation,
  commandBar,
  footer,
  productName = "Mythos-Lite",
  productDescription = "授权漏洞研究",
}: AppShellProps) {
  return (
    <div className="precision-ops min-h-screen bg-background text-foreground">
      <div className="grid min-h-screen md:grid-cols-[15rem_minmax(0,1fr)]">
        <aside className="hidden border-r border-border bg-[var(--surface)] md:flex md:flex-col">
          <div className="border-b border-border px-5 py-4">
            <p className="text-sm font-semibold">{productName}</p>
            <p className="mt-1 text-xs text-muted-foreground">{productDescription}</p>
          </div>
          <nav aria-label="主导航" className="flex-1 space-y-1 p-3">
            {navigation.map(({ href, label, icon: Icon, active, badge }) => (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "flex min-h-9 items-center gap-3 rounded-md px-3 text-sm text-muted-foreground outline-none transition-colors hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring",
                  active && "bg-primary/12 text-primary",
                )}
              >
                <Icon aria-hidden="true" className="size-4" />
                <span className="min-w-0 flex-1 truncate">{label}</span>
                {badge}
              </Link>
            ))}
          </nav>
          {footer ? <div className="border-t border-border p-3">{footer}</div> : null}
        </aside>
        <div className="min-w-0">
          <div className="flex min-h-14 items-center justify-between border-b border-border bg-[var(--surface-glass)] px-4 backdrop-blur-md md:hidden">
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold">{productName}</p>
              <p className="truncate text-xs text-muted-foreground">{productDescription}</p>
            </div>
            <Sheet>
              <SheetTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  className="size-10 shrink-0"
                  aria-label="打开主导航"
                >
                  <Menu aria-hidden="true" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-[min(88vw,20rem)]">
                <SheetHeader className="border-b border-border">
                  <SheetTitle>{productName}</SheetTitle>
                  <SheetDescription>{productDescription}</SheetDescription>
                </SheetHeader>
                <nav aria-label="移动主导航" className="space-y-1 px-3">
                  {navigation.map(({ href, label, icon: Icon, active, badge }) => (
                    <SheetClose key={href} asChild>
                      <Link
                        href={href}
                        aria-current={active ? "page" : undefined}
                        className={cn(
                          "flex min-h-11 items-center gap-3 rounded-md px-3 text-sm text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring",
                          active && "bg-primary/12 text-primary",
                        )}
                      >
                        <Icon aria-hidden="true" className="size-4" />
                        <span className="min-w-0 flex-1 truncate">{label}</span>
                        {badge}
                      </Link>
                    </SheetClose>
                  ))}
                </nav>
                {footer ? <div className="mt-auto border-t border-border p-3">{footer}</div> : null}
              </SheetContent>
            </Sheet>
          </div>
          {commandBar ? (
            <header className="sticky top-0 z-30 border-b border-border bg-[var(--surface-glass)] backdrop-blur-md">
              {commandBar}
            </header>
          ) : null}
          <main className="min-w-0">{children}</main>
        </div>
      </div>
    </div>
  );
}
