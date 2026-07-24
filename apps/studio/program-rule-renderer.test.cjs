const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  PROGRAM_RULE_RENDER_LIMITS,
  createProgramRuleRenderer,
} = require("./program-rule-renderer.cjs");

const URL = "https://rules.example.test/program";

test("renderer lazily creates an isolated proxied browser and returns a bounded envelope", async () => {
  const harness = createHarness({
    bodyValues: ["Loading", "In scope: api.example.test", "In scope: api.example.test"],
    serverAddress: { ipAddress: "127.0.0.1", port: 39001 },
  });
  assert.equal(harness.launchCalls.length, 0);

  const result = await harness.renderer.render({ depth: 0, url: URL });

  assert.deepEqual(harness.launchCalls, [{ headless: true }]);
  assert.deepEqual(harness.browser.newContextCalls, [{
    acceptDownloads: false,
    proxy: { server: "http://127.0.0.1:39001" },
    serviceWorkers: "block",
  }]);
  assert.deepEqual(harness.lifecycle.slice(0, 5), [
    "proxy", "launch", "route", "routeWebSocket", "newPage",
  ]);
  assert.ok(harness.lifecycle.indexOf("newPage") < harness.lifecycle.indexOf("goto"));
  assert.deepEqual(harness.page.gotoCalls, [{
    options: { timeout: 10_000, waitUntil: "domcontentloaded" },
    url: URL,
  }]);
  assert.deepEqual(result, {
    document: {
      anchors: [{
        href: "https://rules.example.test/api-docs",
        is_attachment: false,
        text: "API docs",
      }],
      content_type: "text/html",
      depth: 0,
      list_items: ["No automated scanning"],
      mode: "browser",
      source_url: URL,
      tables: [[["Asset", "Status"], ["api.example.test", "in scope"]]],
      visible_strings: ["In scope: api.example.test"],
    },
    proxy_observed: true,
  });
  assert.equal(harness.context.closeCalls, 1);
  assert.equal(harness.browser.closeCalls, 1);
  assert.equal(harness.proxy.closeCalls, 1);
  assert.ok(harness.now() <= 2_000);
});

test("route guard permits only exact-origin bounded GET and HEAD requests", async () => {
  const routed = [];
  const harness = createHarness({
    gotoHook: async ({ context }) => {
      for (let index = 0; index < PROGRAM_RULE_RENDER_LIMITS.maxRequests + 1; index += 1) {
        routed.push(await context.dispatchRoute(new FakeRequest({
          method: index === 1 ? "HEAD" : "GET",
          resourceType: index === 1 ? "fetch" : "document",
          url: URL,
        })));
      }
      routed.push(await context.dispatchRoute(new FakeRequest({
        method: "POST",
        resourceType: "fetch",
        url: URL,
      })));
      routed.push(await context.dispatchRoute(new FakeRequest({
        resourceType: "document",
        url: "https://other.example.test/program",
      })));
      routed.push(await context.dispatchRoute(new FakeRequest({
        redirected: true,
        resourceType: "document",
        url: URL,
      })));
      routed.push(await context.dispatchRoute(new FakeRequest({
        resourceType: "media",
        url: URL,
      })));
    },
  });

  await harness.renderer.render({ depth: 0, url: URL });

  assert.deepEqual(routed.slice(0, PROGRAM_RULE_RENDER_LIMITS.maxRequests).map(action),
    Array(PROGRAM_RULE_RENDER_LIMITS.maxRequests).fill("continue"));
  assert.ok(routed.slice(PROGRAM_RULE_RENDER_LIMITS.maxRequests).every((route) => (
    action(route) === "abort"
  )));
  assert.ok(routed.every((route) => route._request.headersCalls === 0));
  assert.ok(routed.every((route) => route._request.postDataCalls === 0));
});

test("renderer closes WebSockets by policy and cancels downloads as terminal failures", async () => {
  const download = new FakeDownload();
  const webSocket = new FakeWebSocketRoute();
  const harness = createHarness({
    gotoHook: async ({ context, page }) => {
      await context.dispatchWebSocket(webSocket);
      page.emit("download", download);
    },
  });

  await assert.rejects(
    harness.renderer.render({ depth: 1, url: URL }),
    safeRendererError("download_rejected"),
  );
  assert.deepEqual(webSocket.closeCalls, [{ code: 1008, reason: "policy" }]);
  assert.equal(webSocket.connectCalls, 0);
  assert.equal(download.cancelCalls, 1);
  assert.equal(harness.context.closeCalls, 1);
  assert.equal(harness.browser.closeCalls, 1);
  assert.equal(harness.proxy.closeCalls, 1);
});

test("close waits for incomplete browser creation and is memoized", async () => {
  const launch = deferred();
  const harness = createHarness({ launchPromise: launch.promise });
  const rendering = harness.renderer.render({ depth: 0, url: URL });
  await Promise.resolve();
  const firstClose = harness.renderer.close("app_exit");
  const secondClose = harness.renderer.close("ignored");
  assert.equal(firstClose, secondClose);

  launch.resolve(harness.browser);
  await assert.rejects(rendering, safeRendererError("program_rule_renderer_closed"));
  await firstClose;

  assert.equal(harness.browser.newContextCalls.length, 0);
  assert.equal(harness.browser.closeCalls, 1);
  assert.equal(harness.proxy.closeCalls, 1);
});

test("serverAddr is advisory and only a boolean observation leaves the renderer", async () => {
  const secretAddress = "198.51.100.77";
  const harness = createHarness({
    serverAddress: { ipAddress: secretAddress, port: 443 },
  });
  const result = await harness.renderer.render({ depth: 0, url: URL });

  assert.equal(result.proxy_observed, false);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secretAddress.replaceAll(".", "\\."), "u"));
});

test("renderer source uses Locator APIs and excludes persistence and capture features", () => {
  const source = fs.readFileSync(path.join(__dirname, "program-rule-renderer.cjs"), "utf8");
  for (const forbidden of [
    "launchPersistentContext",
    "storageState",
    "recordHar",
    "recordVideo",
    "screenshot",
    ".evaluate(",
    "addInitScript",
    "httpCredentials",
    "clientCertificates",
    "networkidle",
  ]) {
    assert.doesNotMatch(source, new RegExp(escapeRegExp(forbidden), "u"));
  }
  assert.match(source, /\.locator\(/u);
  assert.match(source, /\.innerText\(/u);
  assert.match(source, /\.getAttribute\(/u);
});

function createHarness({
  bodyValues = ["In scope", "In scope"],
  gotoHook = null,
  launchPromise = null,
  serverAddress = null,
} = {}) {
  const lifecycle = [];
  let clock = 0;
  const page = new FakePage({ bodyValues, gotoHook, lifecycle, serverAddress });
  const context = new FakeContext({ lifecycle, page });
  page.context = context;
  const browser = new FakeBrowser({ context });
  const proxy = {
    closeCalls: 0,
    host: "127.0.0.1",
    port: 39001,
    proxyUrl: "http://127.0.0.1:39001",
    async close() { this.closeCalls += 1; },
  };
  const launchCalls = [];
  const renderer = createProgramRuleRenderer({
    browserType: {
      async launch(options) {
        lifecycle.push("launch");
        launchCalls.push(options);
        return launchPromise ? launchPromise : browser;
      },
    },
    async createProxy(options) {
      lifecycle.push("proxy");
      assert.deepEqual(options, { allowedOrigin: "https://rules.example.test" });
      return proxy;
    },
    now: () => clock,
    async wait(ms) { clock += ms; },
  });
  return {
    browser,
    context,
    launchCalls,
    lifecycle,
    now: () => clock,
    page,
    proxy,
    renderer,
  };
}

class FakeBrowser {
  constructor({ context }) {
    this.closeCalls = 0;
    this.context = context;
    this.newContextCalls = [];
  }

  async newContext(options) {
    this.newContextCalls.push(options);
    return this.context;
  }

  async close() {
    this.closeCalls += 1;
  }
}

class FakeContext {
  constructor({ lifecycle, page }) {
    this.closeCalls = 0;
    this.lifecycle = lifecycle;
    this.page = page;
    this.routeHandler = null;
    this.webSocketHandler = null;
  }

  async route(matcher, handler) {
    assert.equal(matcher, "**/*");
    this.lifecycle.push("route");
    this.routeHandler = handler;
  }

  async routeWebSocket(matcher, handler) {
    assert.equal(matcher, "**/*");
    this.lifecycle.push("routeWebSocket");
    this.webSocketHandler = handler;
  }

  async newPage() {
    this.lifecycle.push("newPage");
    return this.page;
  }

  async dispatchRoute(request) {
    const route = new FakeRoute(request);
    await this.routeHandler(route);
    return route;
  }

  async dispatchWebSocket(route) {
    await this.webSocketHandler(route);
  }

  async close() {
    this.closeCalls += 1;
  }
}

class FakePage extends EventEmitter {
  constructor({ bodyValues, gotoHook, lifecycle, serverAddress }) {
    super();
    this.body = new SequenceBodyLocator(bodyValues);
    this.context = null;
    this.gotoCalls = [];
    this.gotoHook = gotoHook;
    this.lifecycle = lifecycle;
    this.serverAddress = serverAddress;
  }

  async goto(url, options) {
    this.lifecycle.push("goto");
    this.gotoCalls.push({ options, url });
    await this.gotoHook?.({ context: this.context, page: this });
    return {
      headerValue: async (name) => name === "content-type" ? "text/html; charset=utf-8" : null,
      serverAddr: async () => this.serverAddress,
    };
  }

  locator(selector) {
    if (selector === "body") return this.body;
    if (selector === "table") return new CollectionLocator([
      new TableLocator([
        ["Asset", "Status"],
        ["api.example.test", "in scope"],
      ]),
    ]);
    if (selector === "li") return new CollectionLocator([], ["No automated scanning"]);
    if (selector === "a[href]") return new CollectionLocator([
      new AnchorLocator({
        download: null,
        href: "https://rules.example.test/api-docs",
        text: "API docs",
      }),
    ]);
    throw new Error(`unexpected locator: ${selector}`);
  }
}

class SequenceBodyLocator {
  constructor(values) {
    this.calls = 0;
    this.values = values;
  }

  async innerText() {
    const value = this.values[Math.min(this.calls, this.values.length - 1)];
    this.calls += 1;
    return value;
  }
}

class CollectionLocator {
  constructor(items, texts = null) {
    this.items = items;
    this.texts = texts;
  }

  async all() { return this.items; }
  async allInnerTexts() { return this.texts ?? []; }
}

class TableLocator {
  constructor(rows) {
    this.rows = rows;
  }

  locator(selector) {
    assert.equal(selector, "tr");
    return new CollectionLocator(this.rows.map((row) => ({
      locator(cellSelector) {
        assert.equal(cellSelector, "th, td");
        return new CollectionLocator([], row);
      },
    })));
  }
}

class AnchorLocator {
  constructor({ download, href, text }) {
    this.download = download;
    this.href = href;
    this.text = text;
  }

  async innerText() { return this.text; }
  async getAttribute(name) {
    if (name === "href") return this.href;
    if (name === "download") return this.download;
    throw new Error(`unexpected attribute: ${name}`);
  }
}

class FakeRequest {
  constructor({ method = "GET", redirected = false, resourceType, url }) {
    this.headersCalls = 0;
    this.methodValue = method;
    this.postDataCalls = 0;
    this.redirected = redirected;
    this.resourceTypeValue = resourceType;
    this.urlValue = url;
  }

  method() { return this.methodValue; }
  redirectedFrom() { return this.redirected ? {} : null; }
  resourceType() { return this.resourceTypeValue; }
  url() { return this.urlValue; }
  headers() { this.headersCalls += 1; throw new Error("headers must not be read"); }
  postData() { this.postDataCalls += 1; throw new Error("body must not be read"); }
}

class FakeRoute {
  constructor(request) {
    this.actions = [];
    this._request = request;
  }

  async abort() { this.actions.push("abort"); }
  async continue() { this.actions.push("continue"); }
  request() { return this._request; }
}

class FakeWebSocketRoute {
  constructor() {
    this.closeCalls = [];
    this.connectCalls = 0;
  }

  async close(options) { this.closeCalls.push(options); }
  connectToServer() { this.connectCalls += 1; }
}

class FakeDownload {
  constructor() { this.cancelCalls = 0; }
  async cancel() { this.cancelCalls += 1; }
}

function action(route) {
  assert.equal(route.actions.length, 1);
  return route.actions[0];
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function safeRendererError(code) {
  return (error) => {
    assert.equal(error?.code, code);
    assert.equal(error?.message, code);
    return true;
  };
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
