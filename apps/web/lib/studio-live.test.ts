import assert from "node:assert/strict";
import test from "node:test";

import {
  buildStudioEventsUrl,
  refreshStudioProjection,
} from "./studio-live.ts";
import {
  toStudioCampaignHunterCandidateCards,
  toStudioCandidateCards,
  toStudioMissionPanel,
} from "./studio-data.ts";

test("studio events URL uses supported campaign filtering and otherwise subscribes globally", () => {
  assert.equal(
    buildStudioEventsUrl("http://127.0.0.1:8000", "campaign-7"),
    "http://127.0.0.1:8000/mythos/control-center/events?campaign_id=campaign-7",
  );
  assert.equal(
    buildStudioEventsUrl("http://127.0.0.1:8000", null),
    "http://127.0.0.1:8000/mythos/control-center/events",
  );
});

test("named invalidation refetches manifest, mission, candidates, and report projection", async () => {
  const calls: string[] = [];
  const projection = await refreshStudioProjection({
    dependencies: {
      async getCampaign() {
        calls.push("campaign");
        return null;
      },
      async getManifest() {
        calls.push("manifest");
        return {
          name: "research",
          runs: [{
            recorded_at: "2026-07-18T03:00:00Z",
            report_markdown_path: "C:/drafts/run-9.md",
            run_id: "run-9",
          }],
        };
      },
      async getMission(_path, runId) {
        calls.push(`mission:${runId}`);
        return { run_id: runId };
      },
      async listCandidates(_path, runId) {
        calls.push(`candidates:${runId}`);
        return { candidates: [{ hypothesis_id: "H-9", vuln_type: "IDOR" }], run_id: runId };
      },
      mapCampaignCandidates: toStudioCampaignHunterCandidateCards,
      mapMission: toStudioMissionPanel,
      mapResearchCandidates: toStudioCandidateCards,
    },
    signal: new AbortController().signal,
    workspacePath: "C:/authorized/research",
  });

  assert.equal(calls[0], "manifest");
  assert.deepEqual(calls.slice(1).sort(), ["candidates:run-9", "mission:run-9"]);
  assert.equal(projection?.latestRunId, "run-9");
  assert.equal(projection?.candidates[0]?.id, "H-9");
  assert.equal(projection?.reportExport?.report_markdown_path, "C:/drafts/run-9.md");
});

test("campaign invalidation refetches the supported campaign projection", async () => {
  const calls: string[] = [];
  const projection = await refreshStudioProjection({
    dependencies: {
      async getCampaign(campaignId) {
        calls.push(`campaign:${campaignId}`);
        return {
          campaign: { id: campaignId },
          research_queue_suggestions: [{
            candidate_status: "needs_review",
            playbook_id: "authorization",
            priority_score: 82,
            queue_key: "campaign-H-1",
            report_submission_allowed: false,
            validation_allowed: false,
          }],
        } as never;
      },
      async getManifest() {
        calls.push("manifest");
        return {
          campaign_hunter_runs: [{
            campaign_id: "campaign-9",
            recorded_at: "2026-07-18T04:00:00Z",
            report_markdown_path: "C:/drafts/campaign-9.md",
          }],
          name: "campaign",
        };
      },
      async getMission() {
        calls.push("mission");
        return null;
      },
      async listCandidates() {
        calls.push("candidates");
        return { candidates: [], run_id: null };
      },
      mapCampaignCandidates: toStudioCampaignHunterCandidateCards,
      mapMission: toStudioMissionPanel,
      mapResearchCandidates: toStudioCandidateCards,
    },
    signal: new AbortController().signal,
    workspacePath: "C:/authorized/campaign",
  });

  assert.deepEqual(calls, ["manifest", "campaign:campaign-9"]);
  assert.equal(projection?.latestCampaignHunterId, "campaign-9");
  assert.equal(projection?.candidates[0]?.id, "campaign-H-1");
  assert.equal(projection?.reportExport?.report_markdown_path, "C:/drafts/campaign-9.md");
});
