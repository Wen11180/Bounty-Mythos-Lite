const REDACTED = "[REDACTED]";

export function safeDisplay(value: unknown, fallback = "Unavailable"): string {
  const text = typeof value === "string" ? value.trim() : String(value ?? "").trim();

  if (!text) {
    return fallback;
  }

  const lowered = text.toLowerCase();
  const secretMarkers = [
    "authorization:",
    "bearer ",
    "cookie:",
    "set-cookie:",
    "policy_text",
    "secret",
    "token",
    "sk-",
  ];

  if (secretMarkers.some((marker) => lowered.includes(marker))) {
    return REDACTED;
  }

  if (
    /\b(api[_-]?key|password|credential)\b/i.test(text) ||
    /\b(real user data|customer data|production user|live user|personal data|pii)\b/i.test(text) ||
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(text) ||
    /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(text)
  ) {
    return REDACTED;
  }

  return text;
}

export function formatLabel(value: unknown, fallback = "Unknown"): string {
  const display = safeDisplay(value, fallback);
  const knownLabels: Record<string, string> = {
    cannot_authorize_execution: "Execution remains review-gated",
    human_approval_required: "Human review required",
    no_execution_permission: "Execution review gated",
    validation_gate_not_approved: "Validation review required",
  };
  const knownLabel = knownLabels[display.trim().toLowerCase()];

  if (knownLabel) {
    return knownLabel;
  }

  return display
    .replace(/:/g, ": ")
    .replace(/[_-]+/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

export function safeStringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map((item) => safeDisplay(item)).filter((item) => item !== "Unavailable");
}

export function safeRecordEntries(record: Record<string, unknown> | undefined): [string, string][] {
  if (!record) {
    return [];
  }

  return Object.entries(record).map(([key, value]) => [
    formatLabel(key),
    safeDisplay(typeof value === "string" ? value : JSON.stringify(value)),
  ]);
}
