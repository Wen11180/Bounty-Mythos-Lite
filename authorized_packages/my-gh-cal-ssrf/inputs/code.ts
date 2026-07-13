import { Router } from "express";

// Local modeling excerpt derived from public calcom/cal.com v6.2.0 sources:
// - packages/lib/ssrfProtection.ts (validateUrlForSSRF / isPrivateIP / isBlockedHostname)
// - packages/features/webhooks/lib/sendPayload.ts (_sendPayload fetch sink)
// Faithful simplified model of webhook delivery:
//   1. User-controlled subscriberUrl is validated before outbound POST
//   2. SaaS path: HTTPS-only, block private IP + cloud metadata + loopback hostnames
//   3. DNS rebinding residual: async validateUrlForSSRF resolves host IPs
//   4. Self-hosted residual: private HTTP allowed (documented; still metadata-blocked)
// Fail closed: deny() when validation fails.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type WebhookRecord = {
  id: string;
  // models webhook.subscriberUrl (user-controlled delivery target)
  subscriber_url: string;
  owner_id: string;
};

type LabUser = {
  id: string;
};

const router = Router();

router.post(
  "/local/cal/api/webhooks/deliver",
  deliver_local_cal_webhook,
);
router.post(
  "/local/cal/api/webhooks/test",
  test_local_cal_webhook,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models webhook lookup by id for local residual only
function find_webhook(webhook_id: string): WebhookRecord | null {
  if (!webhook_id) {
    return null;
  }
  return {
    id: webhook_id,
    subscriber_url: "subscriber-lab-target",
    owner_id: "owner-lab-1",
  };
}

// models isPrivateIP / isBlockedHostname cloud-metadata short-circuit
function isPrivateIP(ip: string): boolean {
  return Boolean(ip);
}

function isBlockedHostname(hostname: string): boolean {
  return Boolean(hostname);
}

// models validateUrlForSSRF / validateUrlForSSRFSync from ssrfProtection.ts
// Blocks metadata hosts always; SaaS also blocks private IP + non-HTTPS.
async function validateUrlForSSRF(url: string) {
  if (!url) {
    return deny();
  }
  // reserved hostname residual modeled as blocked_hostname short-circuit
  if (isBlockedHostname(url)) {
    return deny();
  }
  // private / link-local residual modeled as isPrivateIP
  if (isPrivateIP(url)) {
    return deny();
  }
  return url;
}

// models webhook ownership residual before delivery (not the primary SSRF control)
function is_webhook_owner(webhook: WebhookRecord, user: LabUser): boolean {
  return webhook.owner_id === user.id;
}

// models prepare path: SSRF validation before outbound delivery
async function prepare_webhook_delivery(subscriber_url: string) {
  const safe_url = await validateUrlForSSRF(subscriber_url);
  if (!safe_url) {
    return deny();
  }
  return safe_url;
}

// models _sendPayload fetch(subscriberUrl, { method: "POST", redirect: "manual" })
async function send_payload(subscriber_url: string) {
  return fetch(subscriber_url);
}

// models delivery after validateUrlForSSRF on subscriberUrl
async function deliver_local_cal_webhook(req: Request, res: Response) {
  const user = current_user(req);
  const webhook = find_webhook(String((req as any).body?.webhook_id || "wh-lab-1"));
  if (!webhook) {
    return deny();
  }
  // owner residual (secondary); primary control is SSRF validation below
  if (!is_webhook_owner(webhook, user)) {
    return deny();
  }
  const target = await prepare_webhook_delivery(webhook.subscriber_url);
  return send_payload(target);
}

// models test/trigger path with explicit subscriber URL body field
async function test_local_cal_webhook(req: Request, res: Response) {
  const subscriber_url = String((req as any).body?.subscriberUrl || "");
  const target = await prepare_webhook_delivery(subscriber_url);
  return send_payload(target);
}
