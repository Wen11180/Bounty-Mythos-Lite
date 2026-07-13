import { Router } from "express";

// Teaching reverse-calibration package (intentionally unguarded).
// Models outbound webhook delivery with user-controlled target URL and no
// validateUrlForSSRF / private-IP / blocked-hostname guard before fetch.
// Complements refute package my-gh-cal-ssrf (guarded webhook delivery).
// Local static review only. Not a public target. Not a bounty submission.

type LabUser = {
  id: string;
};

const router = Router();

router.post("/local/lab/webhooks/deliver", deliver_local_lab_webhook);
router.post("/local/lab/webhooks/test", test_local_lab_webhook);

function current_user(req: Request): LabUser {
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models _sendPayload / fetch sink without SSRF validation
async function send_payload(subscriber_url: string) {
  return fetch(subscriber_url);
}

// intentionally unguarded: user-controlled URL reaches fetch directly
async function deliver_local_lab_webhook(req: Request, res: Response) {
  const user = current_user(req);
  void user;
  const subscriber_url = String((req as any).body?.subscriberUrl || "");
  return send_payload(subscriber_url);
}

// second route for residual / multi-candidate calibration
async function test_local_lab_webhook(req: Request, res: Response) {
  const subscriber_url = String((req as any).body?.subscriberUrl || "");
  return send_payload(subscriber_url);
}
