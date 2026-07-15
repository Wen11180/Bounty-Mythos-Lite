const { createHash } = require("node:crypto");

const allowedOperations = new Set([
  "create_sessions",
  "start_recording",
  "stop_recording",
  "run_trial",
  "close_sessions",
]);
const allowedMethodsByAction = {
  read_only_replay: new Set(["GET", "HEAD"]),
  reversible_update: new Set(["PATCH", "POST", "PUT"]),
  test_object_create: new Set(["POST"]),
};
const allowedParameterTypes = new Set([
  "boolean",
  "integer",
  "number",
  "object_alias",
  "slug",
  "string",
  "ulid",
  "uuid",
]);
const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
const authenticationRoutePattern = /(?:^|[\/_-])(?:auth|authentication|callback|login|oauth2?|oidc|saml|sessions?|sign[-_]?in|sso|token)(?:[\/_.-]|$)/i;
const challengeRoutePattern = /(?:captcha|challenge|cdn-cgi)/i;
const sensitiveParameterPattern = /(?:authorization|cookie|credential|password|secret|token)/i;
const sensitiveRouteValuePattern = /(?:authorization|cookie|credential|password|secret|token)\s*[:=]/i;
const maxIpcLineBytes = 64 * 1024;
const maxInputDepth = 16;
const forbiddenInputKeys = new Set([
  "authorization",
  "body",
  "cookies",
  "credentials",
  "headers",
  "object_id",
  "object_ids",
  "password",
  "query_values",
  "remote_port",
  "response_content",
  "script",
  "token",
  "url",
  "network_listener",
  "down" + "loads",
  "screen" + "shots",
  "stor" + "age",
  "stor" + "age_state",
]);

function createBlackBoxRunner(options = {}) {
  return new BlackBoxRunner(options);
}

function createAppExitHandler({ closeSessions, exit, killChildren }) {
  let shutdown = null;
  return function handleBeforeQuit(event) {
    event.preventDefault();
    if (!shutdown) {
      shutdown = (async () => {
        await closeSessions("app_exit");
        killChildren();
        exit(0);
      })();
    }
    return shutdown;
  };
}

class BlackBoxRunner {
  constructor(options) {
    this.browserType = options.browserType ?? null;
    this.now = options.now ?? Date.now;
    this.setTimer = options.setTimer ?? setTimeout;
    this.clearTimer = options.clearTimer ?? clearTimeout;
    this.emit = options.emit ?? (() => {});
    this.browser = null;
    this.expiryTimer = null;
    this.lease = null;
    this.sessions = new Map();
    this.workflows = new Map();
    this.recordedWorkflows = new Map();
    this.pendingRequests = new WeakMap();
    this.ignoredRequests = new WeakSet();
    this.listeners = [];
    this.traces = [];
    this.state = "idle";
    this.stopEvent = null;
    this.activeTrial = null;
    this.closing = false;
    this.closePromise = null;
    this.creationPromise = null;
    this.creatingSessions = false;
    this.lifecycleGeneration = 0;
    this.shutdown = false;
    this.queue = Promise.resolve();
  }

  async createSessions(payload) {
    assertNoForbiddenInput(payload);
    if (this.shutdown) {
      throw new Error("runner_shutdown");
    }
    if (this.closing || this.closePromise) {
      throw new Error("sessions_closing");
    }
    if (this.browser || this.creatingSessions) {
      throw new Error("sessions_already_created");
    }

    const request = validateSessionRequest(payload, this.now());
    const generation = this.lifecycleGeneration;
    this.creatingSessions = true;
    const creationPromise = this._createSessions(request, generation);
    this.creationPromise = creationPromise;
    try {
      return await creationPromise;
    } finally {
      if (this.creationPromise === creationPromise) {
        this.creationPromise = null;
      }
      this.creatingSessions = false;
    }
  }

  async _createSessions(request, generation) {
    const browserType = this.browserType ?? require("playwright").chromium;
    let browser;
    try {
      browser = await browserType.launch({ headless: false });
    } catch {
      if (!this._isCreationCurrent(generation)) {
        throw new Error("session_creation_cancelled");
      }
      throw new Error("browser_launch_failed");
    }

    const records = [];
    try {
      this._assertCreationCurrent(generation);
      for (const session of request.sessions) {
        const context = await browser.newContext({
          acceptDownloads: false,
          serviceWorkers: "block",
        });
        records.push({ ...session, context, page: null });
        this._assertCreationCurrent(generation);
        await context.route("**/*", (route) =>
          this._guardRoute(route, request.lease, generation),
        );
        this._assertCreationCurrent(generation);
        const page = await context.newPage();
        this._assertCreationCurrent(generation);
        records.at(-1).page = page;
      }

      this.browser = browser;
      this.lease = request.lease;
      this.stopEvent = null;
      for (const record of records) {
        this.sessions.set(record.session_alias, record);
      }
      browser.on("disconnected", () => {
        if (generation === this.lifecycleGeneration && !this.closing) {
          this._enqueue(() => this._stopOnce("browser_crash"));
        }
      });
      for (const record of records) {
        const { page } = record;
        page.on("close", () => {
          if (generation === this.lifecycleGeneration && !this.closing) {
            this._enqueue(() => this._stopOnce("page_closed"));
          }
        });
        page.on("crash", () => {
          if (generation === this.lifecycleGeneration && !this.closing) {
            this._enqueue(() => this._stopOnce("browser_crash"));
          }
        });
      }
    } catch (error) {
      await Promise.allSettled(records.map(({ context }) => context.close()));
      try {
        await browser.close();
      } catch {
        // The browser may have failed while its contexts were being created.
      }
      if (error?.message === "session_creation_cancelled") {
        throw error;
      }
      throw new Error("session_creation_failed");
    }

    const expiryDelay = request.lease.expires_at_ms - this.now();
    this.expiryTimer = this.setTimer(
      () => generation === this.lifecycleGeneration
        ? this._stopOnce("lease_expired")
        : undefined,
      expiryDelay,
    );
    this.state = "awaiting_sessions_ready";
    return this._safeEvent({
      event: "sessions_created",
      session_aliases: request.sessions.map((session) => session.session_alias),
      state: this.state,
    });
  }

  async startRecording(payload) {
    assertNoForbiddenInput(payload);
    if (this.stopEvent) {
      return this._safeEvent(this.stopEvent);
    }
    if (!this.browser || this.state !== "awaiting_sessions_ready") {
      throw new Error("sessions_required");
    }
    if (payload?.sessions_ready !== true) {
      throw new Error("sessions_ready_required");
    }
    if (!Array.isArray(payload.workflows) || payload.workflows.length < 1) {
      throw new Error("recorded_workflows_required");
    }

    const workflows = payload.workflows.map((workflow) =>
      validateWorkflow(workflow, this.lease, this.sessions),
    );
    if (new Set(workflows.map((workflow) => workflow.aliases.workflow_alias)).size !== workflows.length) {
      throw new Error("unique_workflow_aliases_required");
    }

    this.workflows = new Map(
      workflows.map((workflow) => [workflow.aliases.workflow_alias, workflow]),
    );
    this.traces = [];
    this.recordedWorkflows.clear();
    this.state = "recording";
    this._attachRecordingListeners();
    return this._safeEvent({ event: "recording_started", state: this.state });
  }

  async stopRecording() {
    if (this.stopEvent) {
      return this._safeEvent(this.stopEvent);
    }
    if (this.state !== "recording") {
      throw new Error("recording_not_active");
    }
    this._detachRecordingListeners();
    await this.queue;
    if (this.stopEvent) {
      return this._safeEvent(this.stopEvent);
    }
    if (this.state !== "recording") {
      throw new Error("recording_not_active");
    }
    this.state = "sessions_ready";
    return this._safeEvent({
      event: "recording_stopped",
      traces: this.traces,
    });
  }

  async runTrial(payload) {
    assertNoForbiddenInput(payload);
    if (this.stopEvent) {
      return this._safeEvent(this.stopEvent);
    }
    if (this.state !== "sessions_ready") {
      throw new Error("recording_must_stop_before_trial");
    }
    if (this.now() >= this.lease.expires_at_ms) {
      return this._stopOnce("lease_expired");
    }
    if (this.activeTrial) {
      throw new Error("trial_already_running");
    }
    if (!payload || !hasOnlyKeys(payload, ["session_alias", "workflow_alias"])) {
      throw new Error("safe_trial_aliases_required");
    }

    const session = this.sessions.get(payload.session_alias);
    const recorded = this.recordedWorkflows.get(payload.workflow_alias);
    if (!session || !recorded) {
      throw new Error("recorded_trial_aliases_required");
    }
    if (!this.lease.active_origins.has(recorded.workflow.origin)) {
      throw new Error("active_origin_not_lease_approved");
    }
    if (!allowedMethodsByAction.read_only_replay.has(recorded.workflow.method)) {
      throw new Error("unsupported_trial_action");
    }

    const trial = { generation: this.lifecycleGeneration };
    this.activeTrial = trial;
    try {
      return await this._runTrial(session, recorded, trial);
    } finally {
      if (this.activeTrial === trial) {
        this.activeTrial = null;
      }
    }
  }

  async _runTrial(session, recorded, trial) {
    const startedAt = this.now();
    let response;
    try {
      response = await session.context.request.fetch(recorded.request_url, {
        failOnStatusCode: false,
        maxRedirects: 0,
        method: recorded.workflow.method,
      });
    } catch {
      const cancelled = this._cancelledTrialResult(trial);
      if (cancelled) {
        return cancelled;
      }
      return this._stopOnce("request_failed");
    }

    let cancelled = this._cancelledTrialResult(trial);
    if (cancelled) {
      return cancelled;
    }
    const stopReason = await this._responseStopReason(response);
    cancelled = this._cancelledTrialResult(trial);
    if (cancelled) {
      return cancelled;
    }
    if (stopReason) {
      return this._stopOnce(stopReason);
    }

    const trace = await this._buildTrace(
      recorded.workflow,
      session,
      response,
      startedAt,
    );
    cancelled = this._cancelledTrialResult(trial);
    if (cancelled) {
      return cancelled;
    }
    const result = this._safeEvent({ event: "trial_result", trace });
    this.emit(result);
    return result;
  }

  async closeSessions(reason = "operator_stop") {
    if (reason === "app_exit") {
      this.shutdown = true;
    }
    if (reason === "lease_expired" || reason === "browser_crash") {
      return this._stopOnce(reason);
    }
    await this._closeResources();
    return this._safeEvent({ event: "sessions_closed", reason });
  }

  async handleLine(line) {
    if (typeof line !== "string") {
      throw new Error("single_line_black_box_message_required");
    }
    if (Buffer.byteLength(line, "utf8") > maxIpcLineBytes) {
      throw new Error("black_box_message_too_large");
    }
    if (
      !line.endsWith("\n")
      || line.slice(0, -1).includes("\n")
      || !line.slice(0, -1).trim()
    ) {
      throw new Error("single_line_black_box_message_required");
    }

    let message;
    try {
      message = JSON.parse(line.slice(0, -1));
    } catch {
      throw new Error("valid_black_box_json_required");
    }
    if (
      !message
      || typeof message !== "object"
      || Array.isArray(message)
      || !hasOnlyKeys(message, ["operation", "payload"])
      || !allowedOperations.has(message.operation)
    ) {
      throw new Error("unsupported_black_box_operation");
    }
    assertNoForbiddenInput(message.payload ?? {});

    const payload = message.payload ?? {};
    if (
      (message.operation === "stop_recording" || message.operation === "close_sessions")
      && (!payload || typeof payload !== "object" || Array.isArray(payload)
        || Object.keys(payload).length !== 0)
    ) {
      throw new Error("empty_black_box_payload_required");
    }
    let result;
    if (message.operation === "create_sessions") {
      result = await this.createSessions(payload);
    } else if (message.operation === "start_recording") {
      result = await this.startRecording(payload);
    } else if (message.operation === "stop_recording") {
      result = await this.stopRecording();
    } else if (message.operation === "run_trial") {
      result = await this.runTrial(payload);
    } else {
      result = await this.closeSessions("operator_stop");
    }
    return `${JSON.stringify(this._safeEvent(result))}\n`;
  }

  async flush() {
    await this.queue;
  }

  _attachRecordingListeners() {
    for (const session of this.sessions.values()) {
      const onRequest = (request) => {
        this._enqueue(() => this._recordRequest(session, request));
      };
      const onResponse = (response) => {
        this._enqueue(() => this._recordResponse(session, response));
      };
      const onRequestFailed = (request) => {
        this._enqueue(() => this._recordRequestFailure(request));
      };
      session.page.on("request", onRequest);
      session.page.on("response", onResponse);
      session.page.on("requestfailed", onRequestFailed);
      this.listeners.push({
        onRequest,
        onRequestFailed,
        onResponse,
        page: session.page,
      });
    }
  }

  _detachRecordingListeners() {
    for (const listener of this.listeners) {
      listener.page.off("request", listener.onRequest);
      listener.page.off("response", listener.onResponse);
      listener.page.off("requestfailed", listener.onRequestFailed);
    }
    this.listeners = [];
  }

  async _recordRequest(session, request) {
    if (this.state !== "recording" || this.stopEvent) {
      return;
    }

    const method = request.method().toUpperCase();
    const parsed = parseUrl(request.url());
    if (!parsed) {
      return this._stopOnce("off_origin_redirect");
    }
    if (isAuthenticationTraffic(request, parsed, method)) {
      this.ignoredRequests.add(request);
      return;
    }
    if (!this.lease.active_origins.has(parsed.origin)) {
      if (this.lease.passive_origins.has(parsed.origin) && isReadOnlyMethod(method)) {
        this.ignoredRequests.add(request);
        return;
      }
      return this._stopOnce("off_origin_redirect");
    }

    const workflow = [...this.workflows.values()].find((candidate) =>
      candidate.aliases.session_alias === session.session_alias
      && candidate.origin === parsed.origin
      && candidate.method === method
      && routeMatches(candidate, parsed),
    );
    if (!workflow) {
      this.ignoredRequests.add(request);
      return;
    }

    this.pendingRequests.set(request, {
      request_url: request.url(),
      started_at: this.now(),
      workflow,
    });
  }

  async _recordResponse(session, response) {
    if (this.state !== "recording" || this.stopEvent) {
      return;
    }
    const request = response.request();
    if (!request || this.ignoredRequests.has(request)) {
      return;
    }
    const pending = this.pendingRequests.get(request);
    if (!pending) {
      return;
    }
    const stopReason = await this._responseStopReason(response);
    if (stopReason) {
      await this._stopOnce(stopReason);
      return;
    }

    this.pendingRequests.delete(request);

    const trace = await this._buildTrace(
      pending.workflow,
      session,
      response,
      pending.started_at,
    );
    this.traces.push(trace);
    this.recordedWorkflows.set(pending.workflow.aliases.workflow_alias, {
      request_url: pending.request_url,
      trace,
      workflow: pending.workflow,
    });
  }

  async _recordRequestFailure(request) {
    if (
      this.state !== "recording"
      || this.stopEvent
      || this.ignoredRequests.has(request)
    ) {
      return;
    }
    const parsed = parseUrl(request.url());
    if (parsed && this.lease.active_origins.has(parsed.origin)) {
      await this._stopOnce("request_failed");
    }
  }

  async _responseStopReason(response) {
    const parsed = parseUrl(response.url());
    if (!parsed || !this.lease.active_origins.has(parsed.origin)) {
      return "off_origin_redirect";
    }
    const status = response.status();
    if (status >= 300 && status < 400) {
      const location = await response.headerValue("location");
      if (location) {
        const destination = parseUrl(location, parsed);
        if (!destination || !this.lease.active_origins.has(destination.origin)) {
          return "off_origin_redirect";
        }
        if (authenticationRoutePattern.test(destination.pathname)) {
          return "session_expired";
        }
      }
    }
    if (status === 429) {
      return "rate_limited";
    }
    if (status === 401 || authenticationRoutePattern.test(parsed.pathname)) {
      return "session_expired";
    }
    const challenge = await response.headerValue("cf-mitigated");
    if (challengeRoutePattern.test(parsed.pathname) || challenge === "challenge") {
      return "captcha_or_waf_detected";
    }
    return null;
  }

  async _buildTrace(workflow, session, response, startedAt) {
    const contentType = await response.headerValue("content-type");
    const statusClass = toStatusClass(response.status());
    const responseSchemaFingerprint = `sha256:${createHash("sha256")
      .update(`${statusClass}|${normalizedContentType(contentType)}`)
      .digest("hex")}`;
    return {
      method: workflow.method,
      route_template: workflow.route_template,
      parameters: [...workflow.path_parameters, ...workflow.query_parameters].map(
        ({ location, name, value_type }) => ({ location, name, value_type }),
      ),
      aliases: {
        account_alias: session.account_alias,
        object_aliases: [...workflow.aliases.object_aliases],
        role_alias: session.role_alias,
        session_alias: session.session_alias,
        workflow_alias: workflow.aliases.workflow_alias,
      },
      status_class: statusClass,
      response_schema_fingerprint: responseSchemaFingerprint,
      timing_bucket: toTimingBucket(this.now() - startedAt),
    };
  }

  _enqueue(task) {
    const result = this.queue.then(task);
    this.queue = result.catch(() => {});
    return result;
  }

  _isCreationCurrent(generation) {
    return generation === this.lifecycleGeneration && !this.closing && !this.shutdown;
  }

  _assertCreationCurrent(generation) {
    if (!this._isCreationCurrent(generation)) {
      throw new Error("session_creation_cancelled");
    }
  }

  async _guardRoute(route, lease, generation) {
    const request = route.request();
    const parsed = parseUrl(request.url());
    const method = request.method().toUpperCase();
    const active = parsed && lease.active_origins.has(parsed.origin);
    const passiveSubresource = parsed
      && lease.passive_origins.has(parsed.origin)
      && isReadOnlyMethod(method)
      && !request.isNavigationRequest();
    if (active || passiveSubresource) {
      await route.continue();
      return;
    }

    await route.abort();
    if (generation === this.lifecycleGeneration && !this.closing && !this.stopEvent) {
      this._enqueue(() => this._stopOnce("off_origin_redirect"));
    }
  }

  _cancelledTrialResult(trial) {
    if (this.activeTrial === trial && trial.generation === this.lifecycleGeneration) {
      return null;
    }
    if (this.stopEvent) {
      return this._safeEvent(this.stopEvent);
    }
    throw new Error("trial_cancelled");
  }

  async _stopOnce(reason) {
    if (this.stopEvent) {
      return this._safeEvent(this.stopEvent);
    }
    this.stopEvent = { event: "stop", reason, terminal: true };
    this.state = "stopped";
    const safeStop = this._safeEvent(this.stopEvent);
    this.emit(safeStop);
    await this._closeResources();
    return safeStop;
  }

  async _closeResources() {
    if (this.closePromise) {
      return this.closePromise;
    }
    const closePromise = this._performCloseResources();
    this.closePromise = closePromise;
    try {
      return await closePromise;
    } finally {
      if (this.closePromise === closePromise) {
        this.closePromise = null;
      }
    }
  }

  async _performCloseResources() {
    if (this.closing) {
      return;
    }
    this.closing = true;
    this.lifecycleGeneration += 1;
    this.activeTrial = null;
    this._detachRecordingListeners();
    if (this.expiryTimer !== null) {
      this.clearTimer(this.expiryTimer);
      this.expiryTimer = null;
    }

    try {
      const creationPromise = this.creationPromise;
      if (creationPromise) {
        await creationPromise.catch(() => {});
      }

      const contexts = [...this.sessions.values()].map((session) => session.context);
      const browser = this.browser;
      this.sessions.clear();
      this.workflows.clear();
      this.recordedWorkflows.clear();
      this.traces = [];
      this.browser = null;
      this.lease = null;
      await Promise.allSettled(contexts.map((context) => context.close()));
      if (browser) {
        try {
          await browser.close();
        } catch {
          // The browser may already be gone after a crash.
        }
      }
      if (!this.stopEvent) {
        this.state = "idle";
      }
    } finally {
      this.closing = false;
    }
  }

  _safeEvent(event) {
    return JSON.parse(JSON.stringify(event));
  }
}

function validateSessionRequest(payload, now) {
  if (
    !payload
    || typeof payload !== "object"
    || Array.isArray(payload)
    || !hasOnlyKeys(payload, ["lease", "sessions"])
  ) {
    throw new Error("safe_session_request_required");
  }
  const lease = payload.lease;
  if (
    !lease
    || typeof lease !== "object"
    || Array.isArray(lease)
    || !hasOnlyKeys(lease, ["active_origins", "expires_at", "passive_origins"])
    || !Array.isArray(lease.active_origins)
    || lease.active_origins.length < 1
    || !Array.isArray(lease.passive_origins)
  ) {
    throw new Error("safe_ephemeral_lease_required");
  }
  const activeOrigins = validateOrigins(lease.active_origins);
  const passiveOrigins = validateOrigins(lease.passive_origins);
  if ([...activeOrigins].some((origin) => passiveOrigins.has(origin))) {
    throw new Error("active_passive_origin_overlap");
  }
  const expiresAt = Date.parse(lease.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    throw new Error("active_lease_expiry_required");
  }

  if (!Array.isArray(payload.sessions) || payload.sessions.length !== 2) {
    throw new Error("exactly_two_sessions_required");
  }
  const sessions = payload.sessions.map((session) => {
    if (
      !session
      || typeof session !== "object"
      || Array.isArray(session)
      || !hasOnlyKeys(session, ["account_alias", "role_alias", "session_alias"])
    ) {
      throw new Error("safe_session_aliases_required");
    }
    return {
      account_alias: safeAlias(session.account_alias),
      role_alias: safeAlias(session.role_alias),
      session_alias: safeAlias(session.session_alias),
    };
  });
  if (
    new Set(sessions.map((session) => session.session_alias)).size !== 2
    || new Set(sessions.map((session) => session.account_alias)).size !== 2
    || new Set(sessions.map((session) => session.session_alias)).difference(
      new Set(["session_a", "session_b"]),
    ).size !== 0
  ) {
    throw new Error("independent_session_aliases_required");
  }

  return {
    lease: {
      active_origins: activeOrigins,
      expires_at_ms: expiresAt,
      passive_origins: passiveOrigins,
    },
    sessions,
  };
}

function validateWorkflow(workflow, lease, sessions) {
  if (
    !workflow
    || typeof workflow !== "object"
    || Array.isArray(workflow)
    || !hasOnlyKeys(workflow, [
      "action",
      "aliases",
      "capture_phase",
      "method",
      "origin",
      "path_parameters",
      "query_parameters",
      "route_template",
    ])
  ) {
    throw new Error("safe_workflow_required");
  }
  if (workflow.capture_phase !== "post_login") {
    throw new Error("post_login_capture_required");
  }

  const method = String(workflow.method ?? "").toUpperCase();
  const allowedMethods = allowedMethodsByAction[workflow.action];
  if (!allowedMethods || !allowedMethods.has(method)) {
    throw new Error("safe_workflow_action_required");
  }
  const origin = exactLoopbackOrigin(workflow.origin);
  const active = lease.active_origins.has(origin);
  const passive = lease.passive_origins.has(origin);
  if (!active && !passive) {
    throw new Error("active_origin_not_lease_approved");
  }
  if (passive && !isReadOnlyMethod(method)) {
    throw new Error("passive_origin_mutation_forbidden");
  }

  const aliases = validateAliases(workflow.aliases, sessions);
  const pathParameters = validateParameters(workflow.path_parameters, "path");
  const queryParameters = validateParameters(workflow.query_parameters, "query");
  const routeTemplate = validateRouteTemplate(workflow.route_template, pathParameters);
  return {
    action: workflow.action,
    aliases,
    method,
    origin,
    path_parameters: pathParameters,
    query_parameters: queryParameters,
    route_template: routeTemplate,
  };
}

function validateAliases(aliases, sessions) {
  if (
    !aliases
    || typeof aliases !== "object"
    || Array.isArray(aliases)
    || !hasOnlyKeys(aliases, [
      "account_alias",
      "object_aliases",
      "role_alias",
      "session_alias",
      "workflow_alias",
    ])
    || !Array.isArray(aliases.object_aliases)
    || aliases.object_aliases.length < 1
  ) {
    throw new Error("safe_workflow_aliases_required");
  }
  const session = sessions.get(aliases.session_alias);
  if (
    !session
    || session.account_alias !== aliases.account_alias
    || session.role_alias !== aliases.role_alias
  ) {
    throw new Error("workflow_session_alias_mismatch");
  }
  return {
    account_alias: safeAlias(aliases.account_alias),
    object_aliases: aliases.object_aliases.map(safeAlias),
    role_alias: safeAlias(aliases.role_alias),
    session_alias: safeAlias(aliases.session_alias),
    workflow_alias: safeAlias(aliases.workflow_alias),
  };
}

function validateParameters(parameters, expectedLocation) {
  if (!Array.isArray(parameters)) {
    throw new Error("safe_parameter_schema_required");
  }
  return parameters.map((parameter) => {
    if (
      !parameter
      || typeof parameter !== "object"
      || Array.isArray(parameter)
      || !hasOnlyKeys(parameter, ["location", "name", "segment", "value_type"])
      || parameter.location !== expectedLocation
      || sensitiveParameterPattern.test(parameter.name)
      || !allowedParameterTypes.has(parameter.value_type)
      || (expectedLocation === "path" && !Number.isInteger(parameter.segment))
      || (expectedLocation === "path" && parameter.segment < 1)
      || (expectedLocation === "query" && parameter.segment !== undefined)
    ) {
      throw new Error("safe_parameter_schema_required");
    }
    return {
      location: expectedLocation,
      name: safeAlias(parameter.name),
      ...(expectedLocation === "path" ? { segment: parameter.segment } : {}),
      value_type: parameter.value_type,
    };
  });
}

function validateRouteTemplate(value, pathParameters) {
  if (
    typeof value !== "string"
    || !value.startsWith("/")
    || value.startsWith("//")
    || value.includes("?")
    || value.includes("#")
    || value.includes("\\")
    || value.includes("%")
  ) {
    throw new Error("normalized_route_template_required");
  }
  if (sensitiveRouteValuePattern.test(value)) {
    throw new Error("sensitive_route_template_forbidden");
  }
  const segments = value.split("/").filter(Boolean);
  if (
    !authenticationRoutePattern.test(value)
    && segments.some((segment) => segment !== "{object}" && isConcreteRouteSegment(segment))
  ) {
    throw new Error("concrete_identifier_route_forbidden");
  }
  for (const parameter of pathParameters) {
    if (parameter.segment > segments.length || segments[parameter.segment - 1] !== "{object}") {
      throw new Error("path_parameter_template_mismatch");
    }
  }
  return value;
}

function validateOrigins(origins) {
  const normalized = origins.map(exactLoopbackOrigin);
  if (new Set(normalized).size !== normalized.length) {
    throw new Error("unique_exact_origins_required");
  }
  return new Set(normalized);
}

function exactLoopbackOrigin(value) {
  const parsed = parseUrl(value);
  if (
    !parsed
    || parsed.protocol !== "http:"
    || !loopbackHosts.has(parsed.hostname)
    || value !== parsed.origin
  ) {
    throw new Error("exact_loopback_origin_required");
  }
  return parsed.origin;
}

function routeMatches(workflow, parsed) {
  const templateSegments = workflow.route_template.split("/").filter(Boolean);
  const actualSegments = parsed.pathname.split("/").filter(Boolean);
  if (templateSegments.length !== actualSegments.length) {
    return false;
  }
  if (
    templateSegments.some((segment, index) =>
      segment !== "{object}" && segment !== actualSegments[index],
    )
  ) {
    return false;
  }
  const allowedQueryNames = new Set(
    workflow.query_parameters.map((parameter) => parameter.name),
  );
  return [...parsed.searchParams.keys()].every((name) => allowedQueryNames.has(name));
}

function isAuthenticationTraffic(request, parsed, method) {
  return authenticationRoutePattern.test(parsed.pathname)
    || (!isReadOnlyMethod(method) && request.isNavigationRequest());
}

function isReadOnlyMethod(method) {
  return method === "GET" || method === "HEAD";
}

function normalizedContentType(value) {
  if (typeof value !== "string" || !value) {
    return "unknown";
  }
  return value.split(";", 1)[0].trim().toLowerCase().slice(0, 64);
}

function toStatusClass(status) {
  if (!Number.isInteger(status) || status < 100 || status > 599) {
    return "network_error";
  }
  return `${Math.floor(status / 100)}xx`;
}

function toTimingBucket(milliseconds) {
  if (milliseconds < 100) {
    return "under_100ms";
  }
  if (milliseconds < 500) {
    return "under_500ms";
  }
  if (milliseconds < 1_000) {
    return "under_1s";
  }
  if (milliseconds < 3_000) {
    return "under_3s";
  }
  return "over_3s";
}

function safeAlias(value) {
  if (
    typeof value !== "string"
    || !/^[a-z][a-z0-9_-]{0,63}$/i.test(value)
    || sensitiveParameterPattern.test(value)
    || isConcreteIdentifier(value)
  ) {
    throw new Error("safe_alias_required");
  }
  return value;
}

function isConcreteIdentifier(value) {
  return /^\d+$/u.test(value)
    || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value)
    || /^[0-9a-hjkmnp-tv-z]{26}$/iu.test(value)
    || /^[0-9a-f]{16,}$/iu.test(value);
}

function isConcreteRouteSegment(value) {
  return isConcreteIdentifier(value)
    || /^[a-z0-9]+(?:[-_][a-z0-9]+)+$/iu.test(value);
}

function assertNoForbiddenInput(value, depth = 0) {
  if (depth > maxInputDepth) {
    throw new Error("black_box_input_too_deep");
  }
  if (Array.isArray(value)) {
    value.forEach((nested) => assertNoForbiddenInput(nested, depth + 1));
    return;
  }
  if (!value || typeof value !== "object") {
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (forbiddenInputKeys.has(key.toLowerCase())) {
      throw new Error("forbidden_black_box_input");
    }
    assertNoForbiddenInput(nested, depth + 1);
  }
}

function hasOnlyKeys(value, allowedKeys) {
  const allowed = new Set(allowedKeys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function parseUrl(value, base) {
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

module.exports = {
  createAppExitHandler,
  createBlackBoxRunner,
};
