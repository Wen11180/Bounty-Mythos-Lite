export const mythosPipelineStages = [
  { label: "Policy", status: "Rule Ready", count: "1", risk: "Human gate" },
  { label: "Target Model", status: "Modeled", count: "3 objects", risk: "Heuristic" },
  { label: "Invariants", status: "Generated", count: "3", risk: "High signal" },
  { label: "Hypotheses", status: "Ranked", count: "3", risk: "Unverified" },
  { label: "Refutation", status: "Blocking", count: "1 reason", risk: "Safety first" },
  { label: "Validation Plan", status: "Drafted", count: "Safe only", risk: "Approval required" },
  { label: "Report Draft", status: "Candidate", count: "1", risk: "Human review" },
];
