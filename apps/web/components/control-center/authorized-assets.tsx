import { ExternalLink, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import Link from "next/link";

import { PanelState } from "@/components/control-center/panel-state";
import { SectionHeader } from "@/components/control-center/section-header";
import { Badge } from "@/components/ui/badge";
import type { ControlCenterSnapshot } from "@/lib/control-center-data";
import { statusToneClassName } from "@/lib/control-center-display";

interface AuthorizedAssetsProps {
  assets: ControlCenterSnapshot["authorizedAssets"];
}

export function AuthorizedAssets({ assets }: AuthorizedAssetsProps) {
  return (
    <section aria-label="授权资产" className="min-w-0 border border-border bg-[var(--surface)]">
      <div className="px-4 pt-4">
        <SectionHeader title="授权资产" description="仅显示 Scope Guard 已建模的目标摘要。" />
      </div>
      {assets.length === 0 ? (
        <PanelState state="empty" detail="先创建授权 Campaign 并完成政策与范围摄入。" />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[38rem] border-collapse text-left text-sm">
            <thead className="border-y border-border bg-muted/35 text-xs text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5 font-medium">目标</th>
                <th className="px-4 py-2.5 font-medium">范围状态</th>
                <th className="px-4 py-2.5 font-medium">Campaign</th>
                <th className="px-4 py-2.5 text-right font-medium">查看</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {assets.slice(0, 6).map((asset) => {
                const ScopeIcon = asset.scopeTone === "safe"
                  ? ShieldCheck
                  : asset.scopeTone === "approval"
                    ? ShieldAlert
                    : ShieldX;
                return (
                <tr key={`${asset.campaignId}-${asset.asset}`} className="hover:bg-muted/25">
                  <td className="max-w-80 px-4 py-3 font-mono text-xs text-foreground">
                    <span className="flex items-center gap-2">
                      <ScopeIcon
                        aria-hidden="true"
                        className={`size-4 shrink-0 ${
                          asset.scopeTone === "safe"
                            ? "text-safe"
                            : asset.scopeTone === "approval"
                              ? "text-approval"
                              : "text-danger"
                        }`}
                      />
                      <span className="truncate">{asset.asset}</span>
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="outline" className={statusToneClassName(asset.scopeTone)}>
                      {asset.scopeLabel}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">{asset.campaignStatus}</td>
                  <td className="px-4 py-3 text-right">
                    <Link
                      href={`/campaigns/${encodeURIComponent(asset.campaignId)}`}
                      aria-label={`查看 ${asset.asset} 的 Campaign`}
                      className="inline-flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      <ExternalLink aria-hidden="true" className="size-4" />
                    </Link>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
