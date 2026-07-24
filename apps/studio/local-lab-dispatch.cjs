const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const aliasPattern = /^[A-Za-z0-9_-]{1,64}$/u;

function createLocalLabDispatchHandler(options) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const closeRunnerSessions = options.closeRunnerSessions ?? (async () => {});
  const getApiBaseUrl = options.getApiBaseUrl;
  const now = options.now ?? Date.now;
  const runRunner = options.runRunner;

  return async function dispatchBlackBoxLine(line, dispatchOptions = {}) {
    const message = parseMessage(line);
    if (!isLocalTrial(message)) {
      return runRunner(line);
    }

    let runnerLine;
    try {
      const isCurrent = dispatchOptions.isCurrent ?? (() => true);
      const request = message.payload.exact_preflight_request;
      if (!isCurrent()) {
        throw new Error("local_lab_dispatch_cancelled");
      }
      const apiBaseUrl = exactLoopbackApiBaseUrl(getApiBaseUrl?.());
      let response;
      try {
        response = await fetchImpl(
          `${apiBaseUrl}/mythos/studio/black-box-lab/runs/preflight`,
          {
            body: JSON.stringify(request),
            headers: { "Content-Type": "application/json" },
            method: "POST",
          },
        );
      } catch {
        throw new Error("fresh_local_lab_preflight_required");
      }
      if (!isCurrent()) {
        throw new Error("local_lab_dispatch_cancelled");
      }
      if (
        !response?.ok
        || !String(response.headers?.get?.("content-type") ?? "")
          .toLowerCase()
          .startsWith("application/json")
      ) {
        throw new Error("fresh_local_lab_preflight_required");
      }

      let facts;
      try {
        facts = await response.json();
      } catch {
        throw new Error("fresh_local_lab_preflight_required");
      }
      const expiresAt = validateDispatchFacts(facts, request, now());
      if (!isCurrent()) {
        throw new Error("local_lab_dispatch_cancelled");
      }
      if (now() >= expiresAt) {
        throw new Error("fresh_local_lab_preflight_required");
      }
      const localPlanBinding = buildLocalPlanBinding(request, facts);

      runnerLine = `${JSON.stringify({
        operation: "run_trial",
        payload: {
          approval_expires_at: facts.expires_at,
          complete_plan_digest: facts.complete_plan_digest,
          local_plan_binding: localPlanBinding,
          session_alias: facts.approved_session_alias,
          workflow_alias: facts.approved_workflow_alias,
        },
      })}\n`;
    } catch (error) {
      await closeRunnerSessions("preflight_failed");
      throw error;
    }
    return runRunner(runnerLine);
  };
}

function parseMessage(line) {
  if (typeof line !== "string" || !line.endsWith("\n")) {
    return null;
  }
  try {
    return JSON.parse(line.slice(0, -1));
  } catch {
    return null;
  }
}

function isLocalTrial(message) {
  return Boolean(
    message
    && message.operation === "run_trial"
    && message.payload
    && typeof message.payload === "object"
    && !Array.isArray(message.payload)
    && !("trial_class" in message.payload),
  );
}

function exactLoopbackApiBaseUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("fresh_local_lab_preflight_required");
  }
  if (
    parsed.protocol !== "http:"
    || !loopbackHosts.has(parsed.hostname)
    || parsed.username
    || parsed.password
    || parsed.pathname !== "/"
    || parsed.search
    || parsed.hash
  ) {
    throw new Error("fresh_local_lab_preflight_required");
  }
  return parsed.origin;
}

function validateDispatchFacts(facts, request, nowMs) {
  const completePlan = request?.complete_plan;
  const sessions = completePlan?.lease_preview?.sessions;
  const workflows = completePlan?.lease_preview?.workflows;
  const expiresAt = Date.parse(facts?.expires_at);
  if (
    !facts
    || typeof facts !== "object"
    || Array.isArray(facts)
    || facts.approval_id !== request?.approval_id
    || facts.validation_run_id !== completePlan?.validation_run_id
    || facts.lease_digest !== request?.lease_digest
    || facts.complete_plan_digest !== request?.complete_plan_digest
    || !digestPattern.test(facts.lease_digest ?? "")
    || !digestPattern.test(facts.complete_plan_digest ?? "")
    || !digestPattern.test(facts.scope_reference ?? "")
    || !aliasPattern.test(facts.approved_session_alias ?? "")
    || !aliasPattern.test(facts.approved_workflow_alias ?? "")
    || !Array.isArray(sessions)
    || !sessions.some((session) => (
      session?.session_alias === facts.approved_session_alias
    ))
    || !Array.isArray(workflows)
    || !workflows.some((workflow) => (
      workflow?.workflow_alias === facts.approved_workflow_alias
    ))
    || typeof facts.plan_digest !== "string"
    || facts.plan_digest.length < 1
    || facts.plan_digest.length > 255
    || facts.local_runner_dispatch_allowed !== true
    || facts.execution_allowed !== false
    || facts.report_submission_allowed !== false
    || !Number.isFinite(expiresAt)
    || nowMs >= expiresAt
  ) {
    throw new Error("fresh_local_lab_preflight_required");
  }
  return expiresAt;
}

function buildLocalPlanBinding(request, facts) {
  const leasePreview = request?.complete_plan?.lease_preview;
  const sessions = leasePreview?.sessions;
  const workflows = leasePreview?.workflows;
  if (
    !leasePreview
    || !Array.isArray(sessions)
    || sessions.length !== 2
    || !Array.isArray(workflows)
    || workflows.length !== 1
  ) {
    throw new Error("fresh_local_lab_preflight_required");
  }
  const workflow = workflows[0];
  if (
    !workflow
    || workflow.workflow_alias !== facts.approved_workflow_alias
    || workflow.origin !== leasePreview.active_origin
    || workflow.action !== "read_only_replay"
    || (workflow.method !== "GET" && workflow.method !== "HEAD")
    || typeof workflow.route_template !== "string"
    || !Array.isArray(workflow.object_aliases)
    || workflow.object_aliases.length < 1
  ) {
    throw new Error("fresh_local_lab_preflight_required");
  }
  const boundSessions = sessions.map((session) => {
    if (
      !session
      || session.ready !== true
      || !aliasPattern.test(session.account_alias ?? "")
      || !aliasPattern.test(session.role_alias ?? "")
      || !aliasPattern.test(session.session_alias ?? "")
    ) {
      throw new Error("fresh_local_lab_preflight_required");
    }
    return {
      account_alias: session.account_alias,
      role_alias: session.role_alias,
      session_alias: session.session_alias,
    };
  });
  if (
    new Set(boundSessions.map((session) => session.session_alias)).size !== 2
    || !boundSessions.some((session) => session.session_alias === workflow.session_alias)
    || !boundSessions.some(
      (session) => session.session_alias === facts.approved_session_alias,
    )
  ) {
    throw new Error("fresh_local_lab_preflight_required");
  }
  return {
    active_origin: leasePreview.active_origin,
    sessions: boundSessions,
    workflow: {
      action: workflow.action,
      method: workflow.method,
      object_aliases: workflow.object_aliases,
      origin: workflow.origin,
      route_template: workflow.route_template,
      session_alias: workflow.session_alias,
      workflow_alias: workflow.workflow_alias,
    },
  };
}

module.exports = { createLocalLabDispatchHandler };
