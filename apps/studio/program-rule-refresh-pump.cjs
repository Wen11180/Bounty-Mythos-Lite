const PROGRAM_RULE_PUMP_LIMITS = Object.freeze({
  maxWakeMs: 60 * 60 * 1_000,
  minWakeMs: 1_000,
});
const statuses = new Set(["completed", "failed", "idle"]);

class ProgramRulePumpError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProgramRulePumpError";
    this.code = code;
  }
}

function createProgramRuleRefreshPump({
  clearTimer = clearTimeout,
  now = Date.now,
  runner,
  setTimer = setTimeout,
} = {}) {
  if (
    !runner
    || typeof runner.kick !== "function"
    || typeof runner.close !== "function"
    || typeof clearTimer !== "function"
    || typeof now !== "function"
    || typeof setTimer !== "function"
  ) {
    throw pumpError("program_rule_pump_config_required");
  }

  let activePromise = null;
  let closePromise = null;
  let closing = false;
  let started = false;
  let timerId = null;

  function start() {
    if (closing) return Promise.reject(pumpError("program_rule_pump_closed"));
    started = true;
    return kick();
  }

  function kick() {
    if (closing) return Promise.reject(pumpError("program_rule_pump_closed"));
    if (activePromise !== null) return activePromise;
    clearScheduledWake();
    const operation = (async () => {
      const result = await drain();
      if (!closing) scheduleWake(result.next_due_at);
      return result;
    })();
    let tracked;
    tracked = operation.finally(() => {
      if (activePromise === tracked) activePromise = null;
    });
    activePromise = tracked;
    return tracked;
  }

  function close(reason = "app_exit") {
    if (closePromise !== null) return closePromise;
    closing = true;
    clearScheduledWake();
    closePromise = (async () => {
      await Promise.allSettled([Promise.resolve().then(() => runner.close(reason))]);
      if (activePromise !== null) await Promise.allSettled([activePromise]);
      clearScheduledWake();
    })();
    return closePromise;
  }

  async function drain() {
    let result = safeStatus(null);
    do {
      try {
        result = safeStatus(await runner.kick());
      } catch {
        result = safeStatus(null);
      }
    } while (!closing && result.processed === true);
    return result;
  }

  function scheduleWake(nextDueAt) {
    if (!started || closing) return;
    const due = typeof nextDueAt === "string" ? Date.parse(nextDueAt) : Number.NaN;
    const requestedDelay = Number.isFinite(due)
      ? Math.max(PROGRAM_RULE_PUMP_LIMITS.minWakeMs, due - now())
      : PROGRAM_RULE_PUMP_LIMITS.maxWakeMs;
    const delay = Math.min(PROGRAM_RULE_PUMP_LIMITS.maxWakeMs, requestedDelay);
    timerId = setTimer(() => {
      timerId = null;
      return kick().catch(() => {});
    }, delay);
  }

  function clearScheduledWake() {
    if (timerId === null) return;
    clearTimer(timerId);
    timerId = null;
  }

  return { close, kick, start };
}

function safeStatus(value) {
  if (
    value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && statuses.has(value.status)
    && typeof value.processed === "boolean"
    && (
      value.next_due_at === null
      || (
        typeof value.next_due_at === "string"
        && value.next_due_at.length <= 64
        && Number.isFinite(Date.parse(value.next_due_at))
      )
    )
  ) {
    return {
      next_due_at: value.next_due_at,
      processed: value.processed,
      status: value.status,
    };
  }
  return { next_due_at: null, processed: false, status: "failed" };
}

function pumpError(code) {
  return new ProgramRulePumpError(code);
}

module.exports = {
  PROGRAM_RULE_PUMP_LIMITS,
  ProgramRulePumpError,
  createProgramRuleRefreshPump,
};
