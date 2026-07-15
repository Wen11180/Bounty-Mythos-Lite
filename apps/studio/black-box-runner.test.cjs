const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");

const {
  createAppExitHandler,
  createBlackBoxRunner,
} = require("./black-box-runner.cjs");

const ACTIVE_ORIGIN = "http://127.0.0.1:4100";
const PASSIVE_ORIGIN = "http://127.0.0.1:4101";
const REMOTE_ORIGIN = "https://api.example.test";
const REMOTE_PASSIVE_ORIGIN = "https://static.example.test";
const OBJECT_ID = "507f1f77bcf86cd799439011";

test("create_sessions launches exactly two isolated ephemeral contexts", async () => {
  const fixture = createFixture();

  const result = await fixture.runner.createSessions(sessionRequest());

  assert.equal(fixture.browserType.launchCalls.length, 1);
  assert.deepEqual(fixture.browserType.launchCalls[0], { headless: false });
  assert.equal(fixture.browser.contexts.length, 2);
  assert.notEqual(fixture.browser.contexts[0], fixture.browser.contexts[1]);
  assert.deepEqual(fixture.browser.newContextCalls, [
    { acceptDownloads: false, serviceWorkers: "block" },
    { acceptDownloads: false, serviceWorkers: "block" },
  ]);
  assert.deepEqual(result, {
    event: "sessions_created",
    session_aliases: ["session_a", "session_b"],
    state: "awaiting_sessions_ready",
  });
});

test("concurrent create_sessions reserves one browser and rejects the second IPC call", async () => {
  const launch = deferred();
  const browser = new FakeBrowser();
  const browserType = {
    launchCalls: [],
    launch(options) {
      this.launchCalls.push(options);
      return launch.promise;
    },
  };
  const fixture = createFixture({ browser, browserType });
  const line = `${JSON.stringify({
    operation: "create_sessions",
    payload: sessionRequest(),
  })}\n`;

  const first = fixture.runner.handleLine(line);
  const secondOutcome = fixture.runner.handleLine(line).then(
    () => ({ allowed: true }),
    (error) => ({ allowed: false, error }),
  );
  await Promise.resolve();
  launch.resolve(browser);

  await first;
  const second = await secondOutcome;
  assert.equal(second.allowed, false);
  assert.match(second.error.message, /sessions_already_created/);
  assert.equal(browserType.launchCalls.length, 1);
  assert.equal(browser.contexts.length, 2);

  await fixture.runner.closeSessions("operator_stop");
  assert.deepEqual(browser.contexts.map((context) => context.closeCalls), [1, 1]);
});

test("stop, expiry, crash, and app exit destroy both contexts", async (t) => {
  for (const scenario of ["operator_stop", "lease_expired", "browser_crash", "app_exit"]) {
    await t.test(scenario, async () => {
      const fixture = createFixture();
      await fixture.runner.createSessions(sessionRequest());

      if (scenario === "lease_expired") {
        await fixture.clock.fireNextTimer();
      } else if (scenario === "browser_crash") {
        fixture.browser.emit("disconnected");
        await fixture.runner.flush();
      } else {
        await fixture.runner.closeSessions(scenario);
      }

      assert.deepEqual(
        fixture.browser.contexts.map((context) => context.closeCalls),
        [1, 1],
      );
      assert.equal(fixture.browser.closeCalls, 1);
    });
  }
});

test("concurrent close_sessions callers await the same cleanup", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());
  const close = deferred();
  for (const context of fixture.browser.contexts) {
    context.close = async function closeContext() {
      this.closeCalls += 1;
      await close.promise;
    };
  }

  const first = fixture.runner.closeSessions("operator_stop");
  let secondFinished = false;
  const second = fixture.runner.closeSessions("operator_stop").then((result) => {
    secondFinished = true;
    return result;
  });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(secondFinished, false);
  assert.deepEqual(
    fixture.browser.contexts.map((context) => context.closeCalls),
    [1, 1],
  );

  close.resolve();
  await Promise.all([first, second]);
  assert.equal(fixture.browser.closeCalls, 1);
});

test("[hardening] close_sessions cancels and awaits a pending browser launch", async () => {
  const launch = deferred();
  const browser = new FakeBrowser();
  const fixture = createFixture({
    browser,
    browserType: {
      launchCalls: [],
      launch() {
        return launch.promise;
      },
    },
  });
  const creation = fixture.runner.createSessions(sessionRequest()).then(
    () => ({ created: true }),
    (error) => ({ created: false, error }),
  );
  await Promise.resolve();

  let closeFinished = false;
  const closing = fixture.runner.closeSessions("operator_stop").then((result) => {
    closeFinished = true;
    return result;
  });
  await Promise.resolve();
  assert.equal(closeFinished, false);
  await assert.rejects(
    fixture.runner.createSessions(sessionRequest()),
    /sessions_closing/,
  );

  launch.resolve(browser);
  const [creationResult, closeResult] = await Promise.all([creation, closing]);
  assert.equal(creationResult.created, false);
  assert.match(creationResult.error.message, /session_creation_cancelled/);
  assert.deepEqual(closeResult, {
    event: "sessions_closed",
    reason: "operator_stop",
  });
  assert.equal(browser.contexts.length, 0);
  assert.equal(browser.closeCalls, 1);
});

test("[hardening] app exit awaits pending launch cleanup and permanently rejects creation", async () => {
  const launch = deferred();
  const browser = new FakeBrowser();
  const fixture = createFixture({
    browser,
    browserType: {
      launchCalls: [],
      launch() {
        return launch.promise;
      },
    },
  });
  const creation = fixture.runner.createSessions(sessionRequest()).catch((error) => error);
  await Promise.resolve();
  const calls = { exit: [], kill: 0 };
  const handler = createAppExitHandler({
    closeSessions: (reason) => fixture.runner.closeSessions(reason),
    exit(code) {
      calls.exit.push(code);
    },
    killChildren() {
      calls.kill += 1;
    },
  });

  const shutdown = handler({ preventDefault() {} });
  await Promise.resolve();
  assert.deepEqual(calls.exit, []);
  launch.resolve(browser);
  const creationError = await creation;
  await shutdown;

  assert.match(creationError.message, /session_creation_cancelled/);
  assert.equal(browser.contexts.length, 0);
  assert.equal(browser.closeCalls, 1);
  assert.equal(calls.kill, 1);
  assert.deepEqual(calls.exit, [0]);
  await assert.rejects(
    fixture.runner.createSessions(sessionRequest()),
    /runner_shutdown/,
  );
});

test("[hardening] create_sessions is rejected while context cleanup is active", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());
  const close = deferred();
  for (const context of fixture.browser.contexts) {
    context.close = async function closeContext() {
      this.closeCalls += 1;
      await close.promise;
    };
  }

  const closing = fixture.runner.closeSessions("operator_stop");
  await Promise.resolve();
  await assert.rejects(
    fixture.runner.createSessions(sessionRequest()),
    /sessions_closing/,
  );

  close.resolve();
  await closing;
});

test("recording requires sessions_ready and excludes login submissions", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());

  await assert.rejects(
    fixture.runner.startRecording({ sessions_ready: false, workflows: [workflow()] }),
    /sessions_ready_required/,
  );

  const page = fixture.browser.contexts[0].page;
  emitExchange(page, {
    request: new FakeRequest({
      method: "POST",
      url: `${ACTIVE_ORIGIN}/login?password=never-return-this`,
      navigation: true,
    }),
    response: new FakeResponse({ status: 302, url: `${ACTIVE_ORIGIN}/login` }),
  });

  await fixture.runner.startRecording({ sessions_ready: true, workflows: [workflow()] });
  emitExchange(page, {
    request: new FakeRequest({
      method: "POST",
      url: `${ACTIVE_ORIGIN}/session/sign-in`,
      navigation: true,
    }),
    response: new FakeResponse({ status: 302, url: `${ACTIVE_ORIGIN}/home` }),
  });
  await fixture.runner.flush();

  assert.deepEqual((await fixture.runner.stopRecording()).traces, []);
});

test("recording ignores responses for login requests that started before sessions_ready", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());
  const page = fixture.browser.contexts[0].page;
  const loginRequest = new FakeRequest({
    method: "POST",
    navigation: true,
    url: `${ACTIVE_ORIGIN}/login`,
  });
  page.emit("request", loginRequest);

  await fixture.runner.startRecording({ sessions_ready: true, workflows: [workflow()] });
  page.emit("response", new FakeResponse({
    request: loginRequest,
    status: 401,
    url: `${ACTIVE_ORIGIN}/login`,
  }));
  await fixture.runner.flush();

  assert.equal(fixture.events.some((event) => event.event === "stop"), false);
  assert.deepEqual((await fixture.runner.stopRecording()).traces, []);
});

test("[hardening] workflows require an explicit post_login capture phase", async (t) => {
  for (const capturePhase of [undefined, "pre_login", "login", "unknown"]) {
    await t.test(String(capturePhase), async () => {
      const fixture = createFixture();
      await fixture.runner.createSessions(sessionRequest());
      const candidate = workflow({ capture_phase: capturePhase });
      if (capturePhase === undefined) {
        delete candidate.capture_phase;
      }

      await assert.rejects(
        fixture.runner.startRecording({
          sessions_ready: true,
          workflows: [candidate],
        }),
        /post_login_capture_required/,
      );
    });
  }
});

test("recording emits only normalized trace fields without raw values", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());
  await fixture.runner.startRecording({ sessions_ready: true, workflows: [workflow()] });

  const request = new FakeRequest({
    url: `${ACTIVE_ORIGIN}/widgets/${OBJECT_ID}?view=private-value`,
  });
  const response = new FakeResponse({
    request,
    status: 200,
    url: request.url(),
    headers: {
      "content-type": "application/json",
      "set-cookie": "session=never-return-this",
    },
    body: "never-return-response-content",
  });
  fixture.browser.contexts[0].page.emit("request", request);
  fixture.clock.advance(75);
  fixture.browser.contexts[0].page.emit("response", response);
  await fixture.runner.flush();

  const { traces } = await fixture.runner.stopRecording();
  assert.equal(traces.length, 1);
  assert.deepEqual(Object.keys(traces[0]).sort(), [
    "aliases",
    "method",
    "parameters",
    "response_schema_fingerprint",
    "route_template",
    "status_class",
    "timing_bucket",
  ]);
  assert.deepEqual(traces[0], {
    method: "GET",
    route_template: "/widgets/{object}",
    parameters: [
      { location: "path", name: "widget_id", value_type: "object_alias" },
      { location: "query", name: "view", value_type: "string" },
    ],
    aliases: {
      account_alias: "account_a",
      object_aliases: ["widget_a"],
      role_alias: "member",
      session_alias: "session_a",
      workflow_alias: "workflow_a",
    },
    status_class: "2xx",
    response_schema_fingerprint: traces[0].response_schema_fingerprint,
    timing_bucket: "under_100ms",
  });
  assert.match(traces[0].response_schema_fingerprint, /^sha256:[0-9a-f]{64}$/);
  assertSafeOutput(traces);
  assert.doesNotMatch(JSON.stringify(traces), new RegExp(`${OBJECT_ID}|private-value|never-return`));
});

test("stop_recording drains matched response work queued before listener detach", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());
  await fixture.runner.startRecording({ sessions_ready: true, workflows: [workflow()] });
  const request = new FakeRequest({
    url: `${ACTIVE_ORIGIN}/widgets/${OBJECT_ID}?view=private-value`,
  });
  const page = fixture.browser.contexts[0].page;
  page.emit("request", request);
  page.emit("response", new FakeResponse({ request, status: 200, url: request.url() }));

  const result = await fixture.runner.stopRecording();

  assert.equal(result.traces.length, 1);
  assert.equal(result.traces[0].route_template, "/widgets/{object}");
});

test("concrete identifier route segments are rejected before recording", async (t) => {
  for (const segment of [
    "123456",
    "customer-alpha",
    "customer_alpha",
    "deadbeef-dead-7eef-8eef-deadbeefdead",
    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "507f1f77bcf86cd799439011",
  ]) {
    await t.test(segment, async () => {
      const fixture = createFixture();
      await fixture.runner.createSessions(sessionRequest());

      await assert.rejects(
        fixture.runner.startRecording({
          sessions_ready: true,
          workflows: [workflow({ path_parameters: [], route_template: `/widgets/${segment}` })],
        }),
        /concrete_identifier_route_forbidden/,
      );
    });
  }
});

test("identifier-shaped aliases are rejected before recording", async (t) => {
  for (const alias of [
    "123456",
    "deadbeef-dead-7eef-8eef-deadbeefdead",
    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "abcdefabcdefabcdefabcdef",
  ]) {
    await t.test(alias, async () => {
      const fixture = createFixture();
      await fixture.runner.createSessions(sessionRequest());
      const base = workflow();

      await assert.rejects(
        fixture.runner.startRecording({
          sessions_ready: true,
          workflows: [
            workflow({
              aliases: { ...base.aliases, object_aliases: [alias] },
            }),
          ],
        }),
        /alias/,
      );
    });
  }
});

test("secret-looking route template values are rejected before recording", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());

  await assert.rejects(
    fixture.runner.startRecording({
      sessions_ready: true,
      workflows: [workflow({
        path_parameters: [],
        route_template: "/widgets/token=raw-secret",
      })],
    }),
    /sensitive_route_template_forbidden/,
  );
});

test("authentication and callback traffic is excluded regardless of method", async (t) => {
  for (const [method, route] of [
    ["GET", "/oauth/authorize"],
    ["POST", "/connect/token"],
    ["GET", "/sso/start"],
    ["POST", "/users/sign_in"],
    ["GET", "/auth/callback"],
    ["GET", "/oauth/callback"],
    ["GET", "/session/callback"],
  ]) {
    await t.test(`${method} ${route}`, async () => {
      const fixture = createFixture();
      await fixture.runner.createSessions(sessionRequest());
      await fixture.runner.startRecording({
        sessions_ready: true,
        workflows: [
          workflow({
            action: method === "GET" ? "read_only_replay" : "test_object_create",
            method,
            path_parameters: [],
            query_parameters: [],
            route_template: route,
          }),
        ],
      });
      const request = new FakeRequest({
        method,
        navigation: true,
        url: `${ACTIVE_ORIGIN}${route}`,
      });
      emitExchange(fixture.browser.contexts[0].page, {
        request,
        response: new FakeResponse({ request, status: 200, url: request.url() }),
      });
      await fixture.runner.flush();

      assert.equal(fixture.events.some((event) => event.event === "stop"), false);
      assert.deepEqual((await fixture.runner.stopRecording()).traces, []);
    });
  }
});

test("active origins must match the lease and passive origins cannot mutate", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());

  await assert.rejects(
    fixture.runner.startRecording({
      sessions_ready: true,
      workflows: [workflow({ origin: "http://127.0.0.1:4999" })],
    }),
    /active_origin_not_lease_approved/,
  );
  await assert.rejects(
    fixture.runner.startRecording({
      sessions_ready: true,
      workflows: [
        workflow({
          action: "reversible_update",
          method: "PATCH",
          origin: PASSIVE_ORIGIN,
        }),
      ],
    }),
    /passive_origin_mutation_forbidden/,
  );
});

test("passive rendering traffic is ignored without becoming a stop or mutation trace", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());
  await fixture.runner.startRecording({ sessions_ready: true, workflows: [workflow()] });

  const request = new FakeRequest({ url: `${PASSIVE_ORIGIN}/assets/app.js` });
  emitExchange(fixture.browser.contexts[0].page, {
    request,
    response: new FakeResponse({ request, status: 200, url: request.url() }),
  });
  await fixture.runner.flush();

  assert.equal(fixture.events.some((event) => event.event === "stop"), false);
  assert.deepEqual((await fixture.runner.stopRecording()).traces, []);
});

test("[hardening] context routes are installed before pages and block service workers", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());

  assert.deepEqual(fixture.browser.newContextCalls, [
    { acceptDownloads: false, serviceWorkers: "block" },
    { acceptDownloads: false, serviceWorkers: "block" },
  ]);
  for (const context of fixture.browser.contexts) {
    assert.deepEqual(context.lifecycle, ["route", "newPage"]);
    assert.equal(context.routes.length, 1);
    assert.equal(context.routes[0].matcher, "**/*");
  }
});

test("[hardening] context route permits exact active and passive subresource traffic", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());
  const context = fixture.browser.contexts[1];

  for (const request of [
    new FakeRequest({ method: "POST", navigation: true, url: `${ACTIVE_ORIGIN}/submit` }),
    new FakeRequest({ method: "GET", resourceType: "script", url: `${PASSIVE_ORIGIN}/app.js` }),
    new FakeRequest({ method: "HEAD", resourceType: "image", url: `${PASSIVE_ORIGIN}/pixel` }),
  ]) {
    const route = await context.dispatchRoute(request);
    assert.deepEqual(route.actions, ["continue"]);
  }
  assert.deepEqual(fixture.events, []);
});

test("[hardening] context route aborts forbidden traffic before one terminal stop", async (t) => {
  for (const [name, request] of [
    ["passive top navigation", new FakeRequest({ navigation: true, url: `${PASSIVE_ORIGIN}/landing` })],
    ["passive mutation", new FakeRequest({ method: "POST", url: `${PASSIVE_ORIGIN}/collect` })],
    ["unknown origin", new FakeRequest({ url: "http://127.0.0.1:4199/app.js" })],
    ["near active origin", new FakeRequest({ url: "http://127.0.0.1:41000/app.js" })],
  ]) {
    await t.test(name, async () => {
      const fixture = createFixture();
      await fixture.runner.createSessions(sessionRequest());

      const route = await fixture.browser.contexts[1].dispatchRoute(request);
      await fixture.runner.flush();

      assert.deepEqual(route.actions, ["abort"]);
      assert.deepEqual(fixture.events, [{
        event: "stop",
        reason: "off_origin_redirect",
        terminal: true,
      }]);
      assert.deepEqual(
        fixture.browser.contexts.map((context) => context.closeCalls),
        [1, 1],
      );
    });
  }
});

test("run_trial replays an internally recorded active route without returning values", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());
  await fixture.runner.startRecording({ sessions_ready: true, workflows: [workflow()] });

  const request = new FakeRequest({
    url: `${ACTIVE_ORIGIN}/widgets/${OBJECT_ID}?view=private-value`,
  });
  const response = new FakeResponse({ request, status: 200, url: request.url() });
  fixture.browser.contexts[0].page.emit("request", request);
  fixture.browser.contexts[0].page.emit("response", response);
  await fixture.runner.flush();
  await fixture.runner.stopRecording();

  fixture.browser.contexts[1].fetchResponse = new FakeResponse({
    status: 403,
    url: request.url(),
  });
  const result = await fixture.runner.runTrial({
    session_alias: "session_b",
    workflow_alias: "workflow_a",
  });

  assert.equal(fixture.browser.contexts[1].fetchCalls.length, 1);
  assert.equal(fixture.browser.contexts[1].fetchCalls[0].url, request.url());
  assert.deepEqual(fixture.browser.contexts[1].fetchCalls[0].options, {
    failOnStatusCode: false,
    maxRedirects: 0,
    method: "GET",
  });
  assert.equal(result.event, "trial_result");
  assert.equal(result.trace.status_class, "4xx");
  assert.equal(result.trace.aliases.session_alias, "session_b");
  assertSafeOutput(result);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(`${OBJECT_ID}|private-value`));
});

test("run_trial stops on an off-origin Location without returning the header value", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(sessionRequest());
  await fixture.runner.startRecording({ sessions_ready: true, workflows: [workflow()] });
  const request = new FakeRequest({ url: `${ACTIVE_ORIGIN}/widgets/${OBJECT_ID}` });
  emitExchange(fixture.browser.contexts[0].page, {
    request,
    response: new FakeResponse({ request, status: 200, url: request.url() }),
  });
  await fixture.runner.flush();
  await fixture.runner.stopRecording();
  const redirectTarget = "https://outside.example.test/login";
  fixture.browser.contexts[1].fetchResponse = new FakeResponse({
    headers: { location: redirectTarget },
    status: 302,
    url: request.url(),
  });

  const result = await fixture.runner.runTrial({
    session_alias: "session_b",
    workflow_alias: "workflow_a",
  });

  assert.deepEqual(result, {
    event: "stop",
    reason: "off_origin_redirect",
    terminal: true,
  });
  assert.doesNotMatch(JSON.stringify(result), /outside\.example\.test/);
});

test("[hardening] run_trial permits only one in-flight replay", async () => {
  const fixture = createFixture();
  const requestUrl = await prepareRecordedTrial(fixture);
  const fetch = deferred();
  fixture.browser.contexts[1].fetchHandler = () => fetch.promise;
  const trialPayload = {
    session_alias: "session_b",
    workflow_alias: "workflow_a",
  };

  const first = fixture.runner.runTrial(trialPayload);
  const second = fixture.runner.runTrial(trialPayload).then(
    () => ({ allowed: true }),
    (error) => ({ allowed: false, error }),
  );
  await Promise.resolve();
  const fetchCallCount = fixture.browser.contexts[1].fetchCalls.length;
  fetch.resolve(new FakeResponse({ status: 200, url: requestUrl }));
  await first;
  const secondResult = await second;

  assert.equal(fetchCallCount, 1);
  assert.equal(secondResult.allowed, false);
  assert.match(secondResult.error.message, /trial_already_running/);
});

test("[hardening] close invalidates a pending trial without a late request_failed stop", async () => {
  const fixture = createFixture();
  await prepareRecordedTrial(fixture);
  const fetch = deferred();
  fixture.browser.contexts[1].fetchHandler = () => fetch.promise;
  const trial = fixture.runner.runTrial({
    session_alias: "session_b",
    workflow_alias: "workflow_a",
  }).then(
    () => ({ cancelled: false }),
    (error) => ({ cancelled: true, error }),
  );
  await Promise.resolve();

  await fixture.runner.closeSessions("operator_stop");
  fetch.reject(new Error("context closed"));
  const outcome = await trial;

  assert.equal(outcome.cancelled, true);
  assert.match(outcome.error.message, /trial_cancelled/);
  assert.equal(
    fixture.events.some((event) => event.event === "trial_result" || event.reason === "request_failed"),
    false,
  );
});

test("[hardening] lease expiry invalidates a pending trial without a late result", async () => {
  const fixture = createFixture();
  const requestUrl = await prepareRecordedTrial(fixture);
  const fetch = deferred();
  fixture.browser.contexts[1].fetchHandler = () => fetch.promise;
  const trial = fixture.runner.runTrial({
    session_alias: "session_b",
    workflow_alias: "workflow_a",
  });
  await Promise.resolve();

  await fixture.clock.fireNextTimer();
  fetch.resolve(new FakeResponse({ status: 200, url: requestUrl }));
  const result = await trial;

  assert.deepEqual(result, {
    event: "stop",
    reason: "lease_expired",
    terminal: true,
  });
  assert.deepEqual(fixture.events, [{
    event: "stop",
    reason: "lease_expired",
    terminal: true,
  }]);
});

test("remote sessions require one untampered single-run HTTPS lease", async () => {
  const fixture = createFixture();
  const created = await fixture.runner.createSessions(remoteSessionRequest());
  assert.equal(created.event, "sessions_created");
  await fixture.runner.closeSessions("operator_stop");

  const tampered = remoteSessionRequest();
  tampered.remote_lease.lease.policy_digest = `sha256:${"d".repeat(64)}`;
  await assert.rejects(
    createFixture().runner.createSessions(tampered),
    /lease_digest_mismatch/,
  );

  const discovered = remoteSessionRequest();
  discovered.remote_lease.root_url = REMOTE_ORIGIN;
  await assert.rejects(
    createFixture().runner.createSessions(discovered),
    /safe_remote_human_lease_required/,
  );

  await assert.rejects(
    createFixture().runner.createSessions(remoteSessionRequest({
      active_origin: "http://api.example.test",
    })),
    /exact_https_remote_origin_required/,
  );

  const readOnly = createFixture();
  await readOnly.runner.createSessions(remoteSessionRequest({
    object_reversible: false,
    rollback_ready: false,
  }));
  await readOnly.runner.closeSessions("operator_stop");
});

test("remote contexts block WebSockets before pages without reading messages", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(remoteSessionRequest());

  assert.deepEqual(
    fixture.browser.contexts.map((context) => context.webSocketRoutes.length),
    [1, 1],
  );
  const socket = new FakeWebSocketRoute();
  await fixture.browser.contexts[0].webSocketRoutes[0].handler(socket);
  await fixture.runner.flush();

  assert.equal(socket.closeCalls, 1);
  assert.equal(socket.connectCalls, 0);
  assert.equal(fixture.events[0].reason, "ambiguous_authority");
});

test("remote recording accepts only the exact leased workflow plan", async () => {
  const fixture = createFixture();
  await fixture.runner.createSessions(remoteSessionRequest());
  await fixture.runner.startRecording({
    sessions_ready: true,
    workflows: [remoteWorkflow()],
  });
  const request = new FakeRequest({
    url: `${REMOTE_ORIGIN}/v1/widgets/${OBJECT_ID}`,
  });
  emitExchange(fixture.browser.contexts[0].page, {
    request,
    response: new FakeResponse({ request, status: 200, url: request.url() }),
  });
  await fixture.runner.flush();
  const stopped = await fixture.runner.stopRecording();
  assert.equal(stopped.traces.length, 1);
  assert.equal(stopped.traces[0].route_template, "/v1/widgets/{object}");

  const mismatch = createFixture();
  await mismatch.runner.createSessions(remoteSessionRequest());
  await assert.rejects(
    mismatch.runner.startRecording({
      sessions_ready: true,
      workflows: [remoteWorkflow({ route_template: "/v1/other/{object}" })],
    }),
    /recorded_remote_workflow_mismatch/,
  );
});

test("remote writes remain fail-closed until an explicit rollback executor exists", async () => {
  let authorizeCalls = 0;
  const fixture = createFixture({
    async authorizeRemoteRequest() {
      authorizeCalls += 1;
      return remoteAllowedDecision();
    },
  });
  await fixture.runner.createSessions(remoteSessionRequest({
    action: "reversible_update",
    allowed_trial_classes: ["reversible_out_of_order_state_transition"],
    method: "PATCH",
  }));
  await fixture.runner.startRecording({
    sessions_ready: true,
    workflows: [remoteWorkflow({ action: "reversible_update", method: "PATCH" })],
  });
  const requestUrl = `${REMOTE_ORIGIN}/v1/widgets/${OBJECT_ID}`;
  const request = new FakeRequest({ method: "PATCH", url: requestUrl });
  emitExchange(fixture.browser.contexts[0].page, {
    request,
    response: new FakeResponse({ request, status: 204, url: requestUrl }),
  });
  await fixture.runner.flush();
  await fixture.runner.stopRecording();

  const stopped = await fixture.runner.runTrial({
    session_alias: "session_b",
    trial_class: "reversible_out_of_order_state_transition",
    workflow_alias: "read_widget_a",
  });

  assert.equal(stopped.reason, "rollback_required");
  assert.equal(authorizeCalls, 0);
  assert.equal(fixture.browser.contexts[1].fetchCalls.length, 0);
});

test("remote trial authorizes before fetch and completes without exposing its grant", async () => {
  const order = [];
  const authorizations = [];
  const completions = [];
  const fixture = createFixture({
    async authorizeRemoteRequest(input) {
      order.push("authorize");
      authorizations.push(input);
      return remoteAllowedDecision();
    },
    async completeRemoteRequest(input) {
      order.push("complete");
      completions.push(input);
      return remoteCompletedDecision();
    },
  });
  const requestUrl = await prepareRemoteRecordedTrial(fixture);
  fixture.browser.contexts[1].fetchHandler = () => {
    order.push("fetch");
    return new FakeResponse({ status: 403, url: requestUrl });
  };

  const result = await fixture.runner.runTrial({
    session_alias: "session_b",
    workflow_alias: "read_widget_a",
    trial_class: "cross_account_object_swap",
  });

  assert.deepEqual(order, ["authorize", "fetch", "complete"]);
  assert.deepEqual(authorizations, [{
    lease_digest: fixture.remoteLeaseDigest,
    request: {
      object_alias: "widget_a",
      session_generation: "session_generation_test",
      target_account_alias: "account_b",
      target_role_alias: "member",
      trial_class: "cross_account_object_swap",
      workflow_alias: "read_widget_a",
    },
  }]);
  assert.deepEqual(completions, [{
    lease_digest: fixture.remoteLeaseDigest,
    outcome: "success",
    request_grant_id: "remote_grant_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  }]);
  assert.equal(result.event, "trial_result");
  assert.equal(result.trace.status_class, "4xx");
  assert.doesNotMatch(JSON.stringify(result), /remote_grant|session_generation/);
});

test("remote authorization denial stops the whole path without fetch or retry", async () => {
  let authorizeCalls = 0;
  const fixture = createFixture({
    async authorizeRemoteRequest() {
      authorizeCalls += 1;
      return remoteStoppedDecision("approval_preflight_changed");
    },
  });
  await prepareRemoteRecordedTrial(fixture);

  const first = await fixture.runner.runTrial({
    session_alias: "session_b",
    workflow_alias: "read_widget_a",
    trial_class: "cross_account_object_swap",
  });
  const second = await fixture.runner.runTrial({
    session_alias: "session_b",
    workflow_alias: "read_widget_a",
    trial_class: "cross_account_object_swap",
  });

  assert.equal(first.reason, "approval_preflight_changed");
  assert.equal(second.reason, "approval_preflight_changed");
  assert.equal(authorizeCalls, 1);
  assert.equal(fixture.browser.contexts[1].fetchCalls.length, 0);
});

test("remote operator close invalidates pending authorization before fetch", async () => {
  const authorization = deferred();
  const serverStop = deferred();
  const fixture = createFixture({
    authorizeRemoteRequest: () => authorization.promise,
    stopRemoteLease: () => serverStop.promise,
  });
  await prepareRemoteRecordedTrial(fixture);
  const trial = fixture.runner.runTrial(remoteTrialRequest());
  const trialCancelled = assert.rejects(trial, /trial_cancelled/);
  await Promise.resolve();

  const close = fixture.runner.closeSessions("operator_stop");
  authorization.resolve(remoteAllowedDecision());
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(fixture.browser.contexts[1].fetchCalls.length, 0);
  serverStop.resolve(remoteStoppedDecision("operator_stop"));
  await close;
  await trialCancelled;
});

test("remote runner independently enforces request count and three-second delay", async () => {
  let authorizeCalls = 0;
  const fixture = createFixture({
    async authorizeRemoteRequest() {
      authorizeCalls += 1;
      return remoteAllowedDecision();
    },
    async completeRemoteRequest() {
      return remoteCompletedDecision();
    },
  });
  const requestUrl = await prepareRemoteRecordedTrial(fixture, {
    request_budget_per_workflow: 2,
  });
  fixture.browser.contexts[1].fetchResponse = new FakeResponse({
    status: 403,
    url: requestUrl,
  });

  const first = await fixture.runner.runTrial(remoteTrialRequest());
  assert.equal(first.event, "trial_result");
  fixture.clock.advance(3_000);
  const second = await fixture.runner.runTrial(remoteTrialRequest());
  assert.equal(second.event, "trial_result");
  fixture.clock.advance(3_000);
  const exhausted = await fixture.runner.runTrial(remoteTrialRequest());

  assert.equal(exhausted.reason, "request_budget_exhausted");
  assert.equal(authorizeCalls, 2);

  const earlyFixture = createFixture({
    authorizeRemoteRequest: async () => remoteAllowedDecision(),
    completeRemoteRequest: async () => remoteCompletedDecision(),
  });
  const earlyUrl = await prepareRemoteRecordedTrial(earlyFixture);
  earlyFixture.browser.contexts[1].fetchResponse = new FakeResponse({
    status: 403,
    url: earlyUrl,
  });
  await earlyFixture.runner.runTrial(remoteTrialRequest());
  const early = await earlyFixture.runner.runTrial(remoteTrialRequest());
  assert.equal(early.reason, "rate_limit");
});

test("remote 2xx cross-account content stops as ambiguous without reading the body", async () => {
  const completions = [];
  const fixture = createFixture({
    authorizeRemoteRequest: async () => remoteAllowedDecision(),
    async completeRemoteRequest(input) {
      completions.push(input);
      return remoteStoppedDecision(input.outcome);
    },
  });
  const requestUrl = await prepareRemoteRecordedTrial(fixture);
  fixture.browser.contexts[1].fetchResponse = new FakeResponse({
    body: "third-party-content-must-never-be-read-or-returned",
    status: 200,
    url: requestUrl,
  });

  const result = await fixture.runner.runTrial(remoteTrialRequest());

  assert.equal(result.reason, "ambiguous_authority");
  assert.equal(completions[0].outcome, "ambiguous_authority");
  assert.doesNotMatch(JSON.stringify(result), /third-party-content/);
});

test("remote response metadata failure completes the grant and stops", async () => {
  const outcomes = [];
  const fixture = createFixture({
    authorizeRemoteRequest: async () => remoteAllowedDecision(),
    async completeRemoteRequest(input) {
      outcomes.push(input.outcome);
      return remoteStoppedDecision(input.outcome);
    },
  });
  const requestUrl = await prepareRemoteRecordedTrial(fixture);
  const response = new FakeResponse({ status: 403, url: requestUrl });
  response.headerValue = async () => {
    throw new Error("response metadata unavailable");
  };
  fixture.browser.contexts[1].fetchResponse = response;

  const result = await fixture.runner.runTrial(remoteTrialRequest());

  assert.equal(result.reason, "unstable_response");
  assert.deepEqual(outcomes, ["unstable_response"]);
});

test("remote 429 and server instability report one terminal completion", async (t) => {
  for (const [status, reason] of [[429, "rate_limited"], [503, "server_error"]]) {
    await t.test(String(status), async () => {
      const outcomes = [];
      const fixture = createFixture({
        authorizeRemoteRequest: async () => remoteAllowedDecision(),
        async completeRemoteRequest(input) {
          outcomes.push(input.outcome);
          return remoteStoppedDecision(input.outcome);
        },
      });
      const requestUrl = await prepareRemoteRecordedTrial(fixture);
      fixture.browser.contexts[1].fetchResponse = new FakeResponse({ status, url: requestUrl });

      const result = await fixture.runner.runTrial(remoteTrialRequest());
      const retry = await fixture.runner.runTrial(remoteTrialRequest());

      assert.equal(result.reason, reason);
      assert.equal(retry.reason, reason);
      assert.deepEqual(outcomes, [reason]);
    });
  }
});

test("remote lease cannot grant report submission or human confirmation", async () => {
  await assert.rejects(
    createFixture().runner.createSessions(remoteSessionRequest({
      human_confirmation_allowed: true,
    })),
    /remote_human_gate_must_remain_blocked/,
  );
  await assert.rejects(
    createFixture().runner.createSessions(remoteSessionRequest({
      report_submission_allowed: true,
    })),
    /remote_human_gate_must_remain_blocked/,
  );
});

test("remote operator close and lease expiry clear server-side execution state", async (t) => {
  for (const reason of ["operator_stop", "lease_expired"]) {
    await t.test(reason, async () => {
      const stops = [];
      const fixture = createFixture({
        async stopRemoteLease(input) {
          stops.push(input);
          return remoteStoppedDecision(input.reason);
        },
      });
      const request = remoteSessionRequest();
      await fixture.runner.createSessions(request);

      if (reason === "lease_expired") {
        await fixture.clock.fireNextTimer();
      } else {
        await fixture.runner.closeSessions(reason);
      }

      assert.deepEqual(stops, [{
        lease_digest: request.remote_lease.lease_digest,
        reason,
      }]);
      assert.deepEqual(
        fixture.browser.contexts.map((context) => context.closeCalls),
        [1, 1],
      );
    });
  }
});

test("before-quit waits for one app-exit cleanup then exits without recursion", async () => {
  const close = deferred();
  const calls = { close: 0, exit: [], kill: 0, prevented: 0 };
  const handler = createAppExitHandler({
    closeSessions(reason) {
      calls.close += 1;
      assert.equal(reason, "app_exit");
      return close.promise;
    },
    exit(code) {
      calls.exit.push(code);
    },
    killChildren() {
      calls.kill += 1;
    },
  });
  const event = {
    preventDefault() {
      calls.prevented += 1;
    },
  };

  const shutdown = handler(event);
  const duplicate = handler(event);
  assert.equal(calls.prevented, 2);
  assert.equal(calls.close, 1);
  assert.deepEqual(calls.exit, []);

  close.resolve();
  await Promise.all([shutdown, duplicate]);
  assert.equal(calls.kill, 1);
  assert.deepEqual(calls.exit, [0]);
});

for (const [name, trigger, expectedReason] of [
  [
    "request failure",
    ({ page }) => page.emit("requestfailed", new FakeRequest({ url: `${ACTIVE_ORIGIN}/widgets/failed` })),
    "request_failed",
  ],
  [
    "HTTP 429",
    ({ page }) => emitExchange(page, {
      request: new FakeRequest({ url: `${ACTIVE_ORIGIN}/widgets/rate-limited` }),
      response: new FakeResponse({ status: 429, url: `${ACTIVE_ORIGIN}/widgets/rate-limited` }),
    }),
    "rate_limited",
  ],
  [
    "off-origin redirect",
    ({ page }) => emitExchange(page, {
      request: new FakeRequest({ url: `${ACTIVE_ORIGIN}/widgets/redirected` }),
      response: new FakeResponse({ status: 302, url: "https://outside.example.test/login" }),
    }),
    "off_origin_redirect",
  ],
  [
    "CAPTCHA or WAF",
    ({ page }) => emitExchange(page, {
      request: new FakeRequest({ url: `${ACTIVE_ORIGIN}/widgets/challenge` }),
      response: new FakeResponse({
        status: 403,
        url: `${ACTIVE_ORIGIN}/cdn-cgi/challenge-platform/check`,
        headers: { "cf-mitigated": "challenge" },
      }),
    }),
    "captcha_or_waf_detected",
  ],
  ["page close", ({ page }) => page.emit("close"), "page_closed"],
  [
    "session expiry",
    ({ page }) => emitExchange(page, {
      request: new FakeRequest({ url: `${ACTIVE_ORIGIN}/widgets/expired` }),
      response: new FakeResponse({ status: 401, url: `${ACTIVE_ORIGIN}/widgets/expired` }),
    }),
    "session_expired",
  ],
]) {
  test(`${name} emits one terminal no-retry stop`, async () => {
    const fixture = createFixture();
    await fixture.runner.createSessions(sessionRequest());
    await fixture.runner.startRecording({ sessions_ready: true, workflows: [workflow()] });

    trigger({ page: fixture.browser.contexts[0].page });
    trigger({ page: fixture.browser.contexts[0].page });
    await fixture.runner.flush();

    const stops = fixture.events.filter((event) => event.event === "stop");
    assert.deepEqual(stops, [{ event: "stop", reason: expectedReason, terminal: true }]);
    assert.deepEqual(
      fixture.browser.contexts.map((context) => context.closeCalls),
      [1, 1],
    );
    const repeated = await fixture.runner.runTrial({
      session_alias: "session_b",
      workflow_alias: "workflow_a",
    });
    assert.deepEqual(repeated, stops[0]);
    assert.equal(fixture.browser.contexts[1].fetchCalls.length, 0);
  });
}

test("line-delimited IPC accepts only the five runner operations and returns safe lines", async () => {
  const fixture = createFixture();
  const createLine = `${JSON.stringify({
    operation: "create_sessions",
    payload: sessionRequest(),
  })}\n`;

  const responseLine = await fixture.runner.handleLine(createLine);
  assert.equal(responseLine.endsWith("\n"), true);
  assert.deepEqual(JSON.parse(responseLine), {
    event: "sessions_created",
    session_aliases: ["session_a", "session_b"],
    state: "awaiting_sessions_ready",
  });
  assertSafeOutput(JSON.parse(responseLine));

  await assert.rejects(
    fixture.runner.handleLine(`${JSON.stringify({ operation: "navigate", payload: {} })}\n`),
    /unsupported_black_box_operation/,
  );
  await assert.rejects(
    fixture.runner.handleLine(`${JSON.stringify({
      operation: "run_trial",
      payload: { script: "return secrets", url: "https://outside.example.test" },
    })}\n`),
    /forbidden_black_box_input/,
  );
  await assert.rejects(
    fixture.runner.handleLine(`${createLine.trim()}\n${createLine.trim()}\n`),
    /single_line_black_box_message_required/,
  );
  await assert.rejects(
    fixture.runner.handleLine(`${JSON.stringify({
      operation: "close_sessions",
      payload: { ignored: true },
    })}\n`),
    /empty_black_box_payload_required/,
  );
  await assert.rejects(
    fixture.runner.handleLine(`${" ".repeat(64 * 1024)}x\n`),
    /black_box_message_too_large/,
  );

  let nested = {};
  for (let depth = 0; depth < 20; depth += 1) {
    nested = { nested };
  }
  await assert.rejects(
    fixture.runner.handleLine(`${JSON.stringify({
      operation: "create_sessions",
      payload: nested,
    })}\n`),
    /black_box_input_too_deep/,
  );
});

test("Studio source keeps a narrow runner bridge and a pinned Playwright runtime", async () => {
  const [runnerSource, main, preload, packageJson, packageLock, workbench] = await Promise.all([
    fs.readFile(path.join(__dirname, "black-box-runner.cjs"), "utf8"),
    fs.readFile(path.join(__dirname, "main.cjs"), "utf8"),
    fs.readFile(path.join(__dirname, "preload.cjs"), "utf8"),
    readJson(path.join(__dirname, "package.json")),
    readJson(path.join(__dirname, "package-lock.json")),
    fs.readFile(
      path.join(__dirname, "..", "web", "app", "studio", "studio-workbench.tsx"),
      "utf8",
    ),
  ]);

  assert.equal(packageJson.dependencies.playwright, "1.61.1");
  assert.equal(packageLock.packages[""].dependencies.playwright, "1.61.1");
  assert.match(runnerSource, /require\("playwright"\)/);
  assert.match(
    runnerSource,
    /\.newContext\(\{\s*acceptDownloads: false,\s*serviceWorkers: "block",?\s*\}\)/,
  );
  assert.doesNotMatch(
    runnerSource,
    /launchPersistentContext|storageState|createServer|\.listen\(|\.evaluate\(|addInitScript|screenshot|downloadsPath/,
  );
  assert.match(main, /mythos:black-box-runner/);
  assert.match(main, /createAppExitHandler/);
  assert.match(main, /event\.preventDefault|handleBeforeQuit/);
  assert.doesNotMatch(main, /void blackBoxRunner\.closeSessions\("app_exit"\)/);
  for (const method of [
    "createBlackBoxSessions",
    "startBlackBoxRecording",
    "stopBlackBoxRecording",
    "runBlackBoxTrial",
    "closeBlackBoxSessions",
  ]) {
    assert.match(preload, new RegExp(method));
    assert.match(workbench, new RegExp(method));
  }
  assert.doesNotMatch(preload, /navigate|evaluate|arbitraryUrl|script/);
});

function sessionRequest(overrides = {}) {
  return {
    lease: {
      active_origins: [ACTIVE_ORIGIN],
      expires_at: new Date(Date.parse("2026-07-14T12:05:00Z")).toISOString(),
      passive_origins: [PASSIVE_ORIGIN],
      ...overrides.lease,
    },
    sessions: [
      { account_alias: "account_a", role_alias: "member", session_alias: "session_a" },
      { account_alias: "account_b", role_alias: "member", session_alias: "session_b" },
    ],
    ...overrides,
  };
}

function workflow(overrides = {}) {
  return {
    action: "read_only_replay",
    aliases: {
      account_alias: "account_a",
      object_aliases: ["widget_a"],
      role_alias: "member",
      session_alias: "session_a",
      workflow_alias: "workflow_a",
    },
    capture_phase: "post_login",
    method: "GET",
    origin: ACTIVE_ORIGIN,
    path_parameters: [
      { location: "path", name: "widget_id", segment: 2, value_type: "object_alias" },
    ],
    query_parameters: [
      { location: "query", name: "view", value_type: "string" },
    ],
    route_template: "/widgets/{object}",
    ...overrides,
  };
}

function remoteSessionRequest(overrides = {}) {
  const activeOrigin = overrides.active_origin ?? REMOTE_ORIGIN;
  const authority = {
    profile: "remote_human_lease",
    lease: {
      lease_id: "remote_lease_test",
      asset: "api.example.test",
      policy_digest: `sha256:${"a".repeat(64)}`,
      scope_digest: `sha256:${"b".repeat(64)}`,
      plan_digest: `sha256:${"c".repeat(64)}`,
      active_origins: [activeOrigin],
      passive_origins: [REMOTE_PASSIVE_ORIGIN],
      account_aliases: ["account_a", "account_b"],
      role_aliases: ["member"],
      allowed_actions: [overrides.action ?? "read_only_replay"],
      rollback_required: true,
      workflow_budget: 1,
      request_budget_per_workflow: overrides.request_budget_per_workflow ?? 2,
      duration_seconds: 300,
      min_interval_seconds: 3,
      issued_at: "2026-07-14T12:00:00Z",
      expires_at: "2026-07-14T12:05:00Z",
    },
    approval_id: "approval_remote_test",
    preflight_id: "validation_remote_test",
    approved_at: "2026-07-14T12:00:00Z",
    workflows: [{
      workflow_index: 1,
      workflow_alias: "read_widget_a",
      source_account_alias: "account_a",
      source_role_alias: "member",
      origin: activeOrigin,
      route_template: "/v1/widgets/{object}",
      method: overrides.method ?? "GET",
      action: overrides.action ?? "read_only_replay",
      object_alias: "widget_a",
      object_owner_alias: "account_a",
      object_state: "active",
      object_reversible: overrides.object_reversible ?? true,
      rollback_ready: overrides.rollback_ready ?? true,
      allowed_trial_classes: overrides.allowed_trial_classes ?? ["cross_account_object_swap"],
    }],
    report_submission_allowed: overrides.report_submission_allowed ?? false,
    human_confirmation_allowed: overrides.human_confirmation_allowed ?? false,
  };
  const leaseDigest = `sha256:${createHash("sha256")
    .update(canonicalJson(authority))
    .digest("hex")}`;
  return {
    remote_lease: { ...authority, lease_digest: leaseDigest },
    sessions: [
      { account_alias: "account_a", role_alias: "member", session_alias: "session_a" },
      { account_alias: "account_b", role_alias: "member", session_alias: "session_b" },
    ],
  };
}

function remoteWorkflow(overrides = {}) {
  return workflow({
    aliases: {
      account_alias: "account_a",
      object_aliases: ["widget_a"],
      role_alias: "member",
      session_alias: "session_a",
      workflow_alias: "read_widget_a",
    },
    origin: REMOTE_ORIGIN,
    path_parameters: [
      { location: "path", name: "widget_id", segment: 3, value_type: "object_alias" },
    ],
    query_parameters: [],
    route_template: "/v1/widgets/{object}",
    ...overrides,
  });
}

function remoteTrialRequest() {
  return {
    session_alias: "session_b",
    workflow_alias: "read_widget_a",
    trial_class: "cross_account_object_swap",
  };
}

function remoteAllowedDecision() {
  return {
    allowed: true,
    reason: "remote_request_authorized",
    request_grant_id: "remote_grant_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    stop: null,
    report_submission_allowed: false,
    human_confirmation_allowed: false,
  };
}

function remoteCompletedDecision() {
  return {
    allowed: true,
    reason: "remote_request_completed",
    request_grant_id: null,
    stop: null,
    report_submission_allowed: false,
    human_confirmation_allowed: false,
  };
}

function remoteStoppedDecision(reason) {
  return {
    allowed: false,
    reason,
    request_grant_id: null,
    stop: { reason, terminal: true },
    report_submission_allowed: false,
    human_confirmation_allowed: false,
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function createFixture(options = {}) {
  const browser = options.browser ?? new FakeBrowser();
  const browserType = options.browserType ?? {
    launchCalls: [],
    async launch(options) {
      this.launchCalls.push(options);
      return browser;
    },
  };
  const clock = createManualClock(Date.parse("2026-07-14T12:00:00Z"));
  const events = [];
  const runner = createBlackBoxRunner({
    authorizeRemoteRequest: options.authorizeRemoteRequest,
    browserType,
    clearTimer: clock.clearTimer,
    completeRemoteRequest: options.completeRemoteRequest,
    createId: () => "test",
    emit(event) {
      events.push(event);
    },
    now: clock.now,
    setTimer: clock.setTimer,
    stopRemoteLease: options.stopRemoteLease,
  });
  return { browser, browserType, clock, events, remoteLeaseDigest: null, runner };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

class FakeBrowser extends EventEmitter {
  constructor() {
    super();
    this.closeCalls = 0;
    this.contexts = [];
    this.newContextCalls = [];
  }

  async newContext(options) {
    this.newContextCalls.push(options);
    const context = new FakeContext();
    this.contexts.push(context);
    return context;
  }

  async close() {
    this.closeCalls += 1;
  }
}

class FakeContext {
  constructor() {
    this.closeCalls = 0;
    this.fetchCalls = [];
    this.fetchHandler = null;
    this.fetchResponse = null;
    this.lifecycle = [];
    this.page = new FakePage();
    this.routes = [];
    this.webSocketRoutes = [];
    this.request = {
      fetch: async (url, options) => {
        this.fetchCalls.push({ options, url });
        if (this.fetchHandler) {
          return this.fetchHandler(url, options);
        }
        if (this.fetchResponse instanceof Error) {
          throw this.fetchResponse;
        }
        return this.fetchResponse;
      },
    };
  }

  async newPage() {
    this.lifecycle.push("newPage");
    return this.page;
  }

  async route(matcher, handler) {
    this.lifecycle.push("route");
    this.routes.push({ handler, matcher });
  }

  async routeWebSocket(matcher, handler) {
    this.lifecycle.push("routeWebSocket");
    this.webSocketRoutes.push({ handler, matcher });
  }

  async dispatchRoute(request) {
    assert.equal(this.routes.length, 1);
    const route = new FakeRoute(request);
    await this.routes[0].handler(route);
    return route;
  }

  async close() {
    this.closeCalls += 1;
  }
}

class FakePage extends EventEmitter {}

class FakeRoute {
  constructor(request) {
    this.actions = [];
    this._request = request;
  }

  async abort() {
    this.actions.push("abort");
  }

  async continue() {
    this.actions.push("continue");
  }

  request() {
    return this._request;
  }
}

class FakeWebSocketRoute {
  constructor() {
    this.closeCalls = 0;
    this.connectCalls = 0;
  }

  async close() {
    this.closeCalls += 1;
  }

  connectToServer() {
    this.connectCalls += 1;
    throw new Error("remote WebSocket must not connect");
  }
}

class FakeRequest {
  constructor({ method = "GET", navigation = false, resourceType = "xhr", url }) {
    this._method = method;
    this._navigation = navigation;
    this._resourceType = resourceType;
    this._url = url;
  }

  headers() {
    throw new Error("raw request headers must not be read");
  }

  isNavigationRequest() {
    return this._navigation;
  }

  method() {
    return this._method;
  }

  postData() {
    throw new Error("raw request body must not be read");
  }

  resourceType() {
    return this._resourceType;
  }

  url() {
    return this._url;
  }
}

class FakeResponse {
  constructor({ body = "", headers = {}, request = null, status, url }) {
    this._body = body;
    this._headers = headers;
    this._request = request;
    this._status = status;
    this._url = url;
  }

  async body() {
    throw new Error(`raw response content must not be read: ${this._body}`);
  }

  async headerValue(name) {
    return this._headers[name.toLowerCase()] ?? null;
  }

  request() {
    return this._request;
  }

  status() {
    return this._status;
  }

  url() {
    return this._url;
  }
}

function emitExchange(page, { request, response }) {
  if (!response._request) {
    response._request = request;
  }
  page.emit("request", request);
  page.emit("response", response);
}

async function prepareRecordedTrial(fixture) {
  await fixture.runner.createSessions(sessionRequest());
  await fixture.runner.startRecording({ sessions_ready: true, workflows: [workflow()] });
  const requestUrl = `${ACTIVE_ORIGIN}/widgets/${OBJECT_ID}?view=private-value`;
  const request = new FakeRequest({ url: requestUrl });
  emitExchange(fixture.browser.contexts[0].page, {
    request,
    response: new FakeResponse({ request, status: 200, url: requestUrl }),
  });
  await fixture.runner.flush();
  await fixture.runner.stopRecording();
  return requestUrl;
}

async function prepareRemoteRecordedTrial(fixture, leaseOverrides = {}) {
  const requestPayload = remoteSessionRequest(leaseOverrides);
  fixture.remoteLeaseDigest = requestPayload.remote_lease.lease_digest;
  await fixture.runner.createSessions(requestPayload);
  await fixture.runner.startRecording({
    sessions_ready: true,
    workflows: [remoteWorkflow()],
  });
  const requestUrl = `${REMOTE_ORIGIN}/v1/widgets/${OBJECT_ID}`;
  const request = new FakeRequest({ url: requestUrl });
  emitExchange(fixture.browser.contexts[0].page, {
    request,
    response: new FakeResponse({ request, status: 200, url: requestUrl }),
  });
  await fixture.runner.flush();
  await fixture.runner.stopRecording();
  return requestUrl;
}

function createManualClock(initialNow) {
  let current = initialNow;
  let nextId = 1;
  const timers = new Map();
  return {
    advance(milliseconds) {
      current += milliseconds;
    },
    clearTimer(id) {
      timers.delete(id);
    },
    async fireNextTimer() {
      const [id, timer] = [...timers.entries()].sort((left, right) => left[1].delay - right[1].delay)[0];
      timers.delete(id);
      current += timer.delay;
      await timer.callback();
    },
    now() {
      return current;
    },
    setTimer(callback, delay) {
      const id = nextId;
      nextId += 1;
      timers.set(id, { callback, delay });
      return id;
    },
  };
}

function assertSafeOutput(value) {
  const forbiddenKeys = /header|cookie|authorization|body|query_value|response_content|download|screenshot|storage|object_id/i;
  visit(value);

  function visit(item) {
    if (Array.isArray(item)) {
      item.forEach(visit);
      return;
    }
    if (!item || typeof item !== "object") {
      return;
    }
    for (const [key, nested] of Object.entries(item)) {
      assert.doesNotMatch(key, forbiddenKeys);
      visit(nested);
    }
  }
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}
