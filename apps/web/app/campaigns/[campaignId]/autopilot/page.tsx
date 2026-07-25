import Link from "next/link";

import { AutopilotCampaignSection } from "@/components/autopilot/autopilot-campaign-section";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignAutopilotPage({ params }: PageProps) {
  const { campaignId } = await params;
  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <Link
        href={`/campaigns/${encodeURIComponent(campaignId)}`}
        className="text-sm text-[var(--muted)]"
      >
        ← 项目控制台
      </Link>
      <header className="mt-4 mb-4">
        <h1 className="text-2xl font-semibold">漏洞赏金自动驾驶</h1>
        <p className="text-sm text-[var(--muted)]">
          仅显示安全投影；权限与停止状态始终由服务端决定。
        </p>
      </header>
      <AutopilotCampaignSection campaignId={campaignId} />
    </main>
  );
}
