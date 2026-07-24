import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const campaignPageUrl = new URL(
  "../app/campaigns/[campaignId]/page.tsx",
  import.meta.url,
);
const sectionUrl = new URL(
  "../components/autopilot/autopilot-campaign-section.tsx",
  import.meta.url,
);
const panelUrl = new URL(
  "../components/autopilot/autopilot-panel.tsx",
  import.meta.url,
);
const studioUrl = new URL("../app/studio/studio-workbench.tsx", import.meta.url);
const primaryE2eUrl = new URL("../e2e/bounty-autopilot.spec.ts", import.meta.url);
const labE2eUrl = new URL("../e2e/bounty-autopilot-lab.spec.ts", import.meta.url);

test("campaign detail and Studio compose the real autopilot campaign section", async () => {
  const [campaignPage, studio] = await Promise.all([
    readFile(campaignPageUrl, "utf8"),
    readFile(studioUrl, "utf8"),
  ]);

  assert.match(campaignPage, /import \{ AutopilotCampaignSection \}/u);
  assert.match(campaignPage, /<AutopilotCampaignSection campaignId=\{campaignId\}/u);
  assert.match(campaignPage, /\/autopilot/u);
  assert.match(studio, /import \{ AutopilotCampaignSection \}/u);
  assert.match(
    studio,
    /latestCampaignHunterId\s*\?\s*\([\s\S]*<AutopilotCampaignSection[\s\S]*campaignId=\{latestCampaignHunterId\}/u,
  );
  assert.match(studio, /id="studio-autopilot"/u);
});

test("autopilot section uses strict parsing, SSE invalidation, polling, and LKG state", async () => {
  const section = await readFile(sectionUrl, "utf8");

  assert.match(section, /getAutopilotCampaignProjection\(campaignId, requestSignal\)/u);
  assert.match(section, /parseAutopilotCampaignProjection/u);
  assert.match(section, /createControlCenterLiveController/u);
  assert.match(section, /executeControlCenterRefresh/u);
  assert.match(section, /buildControlCenterEventsUrl/u);
  assert.match(section, /ControlCenterLiveState/u);
  assert.match(section, /projection \?\?/u);
  assert.doesNotMatch(section, /emptyAutopilotProjection\(campaignId\)[,\s\r\n]*\)/u);
});

test("autopilot controls expose exact R3 diff and a two-step emergency stop", async () => {
  const panel = await readFile(panelUrl, "utf8");

  assert.match(panel, /approval\.exact_diff/u);
  assert.match(panel, /autopilot-emergency-stop-confirmation/u);
  assert.match(panel, /autopilot-emergency-stop-confirm/u);
  assert.match(panel, /autopilot-emergency-stop-cancel/u);
  assert.match(panel, /add_hypothesis_guidance/u);
  assert.match(panel, /set_priority/u);
  assert.match(panel, /Research Queue/u);
  assert.doesNotMatch(panel, /onClick=\{onEmergencyStop\}/u);
});

test("autopilot E2E coverage renders routed application pages instead of static HTML", async () => {
  const [primaryE2e, labE2e] = await Promise.all([
    readFile(primaryE2eUrl, "utf8"),
    readFile(labE2eUrl, "utf8"),
  ]);

  assert.match(primaryE2e, /page\.goto\("\/campaigns\/camp_lab\/autopilot"\)/u);
  assert.match(primaryE2e, /autopilot-emergency-stop-confirm/u);
  assert.match(primaryE2e, /exact_diff/u);
  assert.match(primaryE2e, /setViewportSize/u);
  assert.match(labE2e, /page\.goto\("\/campaigns\/camp_lab\/autopilot"\)/u);
  assert.doesNotMatch(`${primaryE2e}\n${labE2e}`, /page\.setContent/u);
});
