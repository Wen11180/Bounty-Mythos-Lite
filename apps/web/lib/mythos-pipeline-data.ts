export const mythosPipelineStages = [
  { label: "Policy", status: "Policy reviewed", count: "1", risk: "Human review gate" },
  { label: "Target Model", status: "Modeled", count: "3 objects", risk: "Heuristic" },
  { label: "Invariants", status: "Generated", count: "3", risk: "High signal" },
  { label: "Hypotheses", status: "Ranked", count: "3", risk: "Unverified" },
  { label: "Refutation", status: "Needs evidence", count: "1 reason", risk: "Safety first" },
  { label: "Validation Plan", status: "Drafted", count: "Safe only", risk: "Review gate required" },
  { label: "Report Draft", status: "Review draft", count: "1", risk: "Human review gate" },
];
