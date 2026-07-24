import { ControlCenterOverview } from "@/components/control-center/control-center-overview";
import { getControlCenterOverview } from "@/lib/api";
import {
  createOfflineControlCenterSnapshot,
  filterControlCenterSnapshot,
  mapControlCenterOverview,
} from "@/lib/control-center-data";

interface RootPageProps {
  searchParams?: Promise<{ campaign_id?: string; q?: string }>;
}

export default async function RootPage({ searchParams }: RootPageProps) {
  const query = await searchParams;
  const campaignId = query?.campaign_id;
  let initialSnapshot;

  try {
    const response = await getControlCenterOverview(campaignId);
    initialSnapshot = mapControlCenterOverview(response);
  } catch (error) {
    initialSnapshot = createOfflineControlCenterSnapshot(
      error instanceof Error ? error.message : "control_center_request_failed",
    );
  }

  return (
    <ControlCenterOverview
      initialSnapshot={filterControlCenterSnapshot(initialSnapshot, query?.q)}
      campaignId={campaignId}
    />
  );
}
