import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiRequestError,
  getAutopilotApprovals,
  getAutopilotAssets,
  getAutopilotBranches,
  getAutopilotBudgets,
  getAutopilotCampaignProjection,
  getAutopilotEvents,
  postAutopilotApprovalDecision,
  postAutopilotEmergencyStop,
  postAutopilotSteering,
  prepareAutopilotEmergencyStop,
} from "./api.ts";

function jsonResponse(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
    status,
  });
}

test("autopilot GET helpers are strict and forward AbortSignal", async () => {
  const originalFetch = globalThis.fetch;
  const controller = new AbortController();
  const calls: Array<{ path: string; signal: AbortSignal | null | undefined }> = [];
  globalThis.fetch = async (input, init) => {
    calls.push({ path: new URL(String(input)).pathname, signal: init?.signal });
    return jsonResponse({ items: [] });
  };

  try {
    await getAutopilotCampaignProjection("campaign / one", controller.signal);
    await getAutopilotAssets("campaign / one", controller.signal);
    await getAutopilotBranches("campaign / one", controller.signal);
    await getAutopilotBudgets("campaign / one", controller.signal);
    await getAutopilotApprovals("campaign / one", controller.signal);
    await getAutopilotEvents("campaign / one", controller.signal);

    assert.deepEqual(
      calls.map((call) => call.path),
      [
        "/mythos/campaigns/campaign%20%2F%20one/autopilot",
        "/mythos/campaigns/campaign%20%2F%20one/autopilot/assets",
        "/mythos/campaigns/campaign%20%2F%20one/autopilot/branches",
        "/mythos/campaigns/campaign%20%2F%20one/autopilot/budgets",
        "/mythos/campaigns/campaign%20%2F%20one/autopilot/approvals",
        "/mythos/campaigns/campaign%20%2F%20one/autopilot/events",
      ],
    );
    assert.equal(calls.every((call) => call.signal === controller.signal), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("autopilot projection GET never replaces a failed request with fallback state", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => jsonResponse({ detail: "projection_unavailable" }, 503);
    await assert.rejects(
      () => getAutopilotCampaignProjection("campaign-1"),
      (error) =>
        error instanceof ApiRequestError &&
        error.status === 503 &&
        error.detail === "projection_unavailable",
    );

    globalThis.fetch = async () => {
      throw new TypeError("offline");
    };
    await assert.rejects(
      () => getAutopilotCampaignProjection("campaign-1"),
      (error) =>
        error instanceof ApiRequestError &&
        error.status === 0 &&
        error.detail === "network_error",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("autopilot mutations send only bounded command fields", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: Record<string, unknown>; path: string }> = [];
  globalThis.fetch = async (input, init) => {
    calls.push({
      body: JSON.parse(String(init?.body)) as Record<string, unknown>,
      path: new URL(String(input)).pathname,
    });
    return jsonResponse({ ok: true });
  };

  try {
    await postAutopilotSteering("campaign / one", {
      branch_id: "branch / one",
      directive: "set_priority",
      priority: 70,
      reason: "operator_priority",
    });
    await postAutopilotSteering("campaign / one", {
      branch_id: "branch / one",
      directive: "add_hypothesis_guidance",
      hypothesis_guidance: "Compare the two owned test-account paths.",
      reason: "operator_hypothesis_guidance",
    });
    await postAutopilotApprovalDecision("campaign / one", "approval / one", {
      actor: "operator",
      decision: "approved",
      reason: "operator_r3_decision",
    });
    await prepareAutopilotEmergencyStop("campaign / one", {
      actor: "operator",
      reason: "operator_emergency_stop",
    });
    await postAutopilotEmergencyStop("campaign / one", {
      actor: "operator",
      confirmation_nonce: "stop-confirmation-1",
      reason: "operator_emergency_stop",
    });

    assert.deepEqual(calls, [
      {
        body: {
          branch_id: "branch / one",
          directive: "set_priority",
          priority: 70,
          reason: "operator_priority",
        },
        path: "/mythos/campaigns/campaign%20%2F%20one/autopilot/steering",
      },
      {
        body: {
          branch_id: "branch / one",
          directive: "add_hypothesis_guidance",
          hypothesis_guidance: "Compare the two owned test-account paths.",
          reason: "operator_hypothesis_guidance",
        },
        path: "/mythos/campaigns/campaign%20%2F%20one/autopilot/steering",
      },
      {
        body: {
          actor: "operator",
          decision: "approved",
          reason: "operator_r3_decision",
        },
        path:
          "/mythos/campaigns/campaign%20%2F%20one/autopilot/approvals/approval%20%2F%20one/decision",
      },
      {
        body: {
          actor: "operator",
          reason: "operator_emergency_stop",
        },
        path:
          "/mythos/campaigns/campaign%20%2F%20one/autopilot/emergency-stop/prepare",
      },
      {
        body: {
          actor: "operator",
          confirmation_nonce: "stop-confirmation-1",
          reason: "operator_emergency_stop",
        },
        path: "/mythos/campaigns/campaign%20%2F%20one/autopilot/emergency-stop",
      },
    ]);

    const steeringPayloads = calls.slice(0, 2).map((call) => JSON.stringify(call.body));
    for (const payload of steeringPayloads) {
      assert.doesNotMatch(
        payload,
        /admitted_asset_ids|branches|budgets|campaign_max|policy|recipe|risk_tier|scope/,
      );
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});
