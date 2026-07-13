import { Router } from "express";

// Local modeling excerpt derived from public knadh/listmonk v6.2.0 sources:
// - cmd/campaigns.go GetCampaign / update / delete handlers
// - cmd/campaigns.go checkCampaignPerm
// - internal/core/campaigns.go CampaignHasLists
// - internal/auth User.HasPerm / GetPermittedLists
// Faithful simplified model: blanket get_all/manage_all OR list-scoped group boundary
// (list ACL represented as group_id for local static recognition).
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type CampaignRecord = {
  id: string;
  // models primary attached list scope used by CampaignHasLists simplified check
  group_id: string;
  name: string;
  body: string;
};

type LabUser = {
  id: string;
  // models listmonk list-scoped permission principal for permitted lists
  group_id: string;
  // models campaigns:get_all / list:get_all blanket
  has_campaigns_get_all: boolean;
  // models campaigns:manage_all / list:manage_all blanket
  has_campaigns_manage_all: boolean;
};

const router = Router();

router.get("/local/listmonk/api/campaigns/:id", get_local_listmonk_campaign);
router.put("/local/listmonk/api/campaigns/:id", update_local_listmonk_campaign);
router.delete("/local/listmonk/api/campaigns/:id", delete_local_listmonk_campaign);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    group_id: String((req as any).user?.group_id || "list-lab-2"),
    has_campaigns_get_all: Boolean((req as any).user?.has_campaigns_get_all ?? false),
    has_campaigns_manage_all: Boolean(
      (req as any).user?.has_campaigns_manage_all ?? false,
    ),
  };
}

// models core.GetCampaign by id
function find_campaign(campaign_id: string): CampaignRecord | null {
  if (!campaign_id) {
    return null;
  }
  return {
    id: campaign_id,
    group_id: "list-lab-1",
    name: "lab-campaign",
    body: "lab-body",
  };
}

// models checkCampaignPerm(PermTypeGet):
// get_all short-circuit OR CampaignHasLists against permitted lists
async function verify_campaign_read_access(campaign_id: string, user: LabUser) {
  const campaign = find_campaign(campaign_id);
  if (!campaign) {
    return deny();
  }
  if (user.has_campaigns_get_all) {
    return campaign;
  }
  // group_id_filter: list-scoped CampaignHasLists simplified single-list model
  if (campaign.group_id !== user.group_id) {
    return deny();
  }
  return campaign;
}

// models checkCampaignPerm(PermTypeManage) before update sink
async function verify_campaign_update_access(campaign_id: string, user: LabUser) {
  const campaign = find_campaign(campaign_id);
  if (!campaign) {
    return deny();
  }
  if (user.has_campaigns_manage_all) {
    return campaign;
  }
  // group_id_filter: manage requires list manage scope / CampaignHasLists
  if (campaign.group_id !== user.group_id) {
    return deny();
  }
  return campaign;
}

// models checkCampaignPerm(PermTypeManage) before delete sink
async function verify_campaign_delete_access(campaign_id: string, user: LabUser) {
  const campaign = find_campaign(campaign_id);
  if (!campaign) {
    return deny();
  }
  if (user.has_campaigns_manage_all) {
    return campaign;
  }
  if (campaign.group_id !== user.group_id) {
    return deny();
  }
  return campaign;
}

// models GET campaign handler
async function get_local_listmonk_campaign(req: Request, res: Response) {
  const user = current_user(req);
  const campaign = await verify_campaign_read_access(req.params.id, user);
  return send_file(campaign.id);
}

// models update campaign handler after manage perm
async function update_local_listmonk_campaign(req: Request, res: Response) {
  const user = current_user(req);
  const campaign = await verify_campaign_update_access(req.params.id, user);
  return update(campaign.id, { name: "lab-updated" });
}

// models delete campaign handler after manage perm
async function delete_local_listmonk_campaign(req: Request, res: Response) {
  const user = current_user(req);
  const campaign = await verify_campaign_delete_access(req.params.id, user);
  return delete_file(campaign.id);
}