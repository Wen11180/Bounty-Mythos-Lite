const { createPinnedConnectProxy, canonicalPublicHttpsUrl } = require("./program-rule-network.cjs");

const PROGRAM_RULE_RENDER_LIMITS = Object.freeze({
  gotoTimeoutMs: 10_000,
  maxAnchors: 500,
  maxBodyCharacters: 524_288,
  maxListItems: 4_000,
  maxRequests: 32,
  maxTables: 64,
  pollIntervalMs: 100,
  stableWindowMs: 2_000,
});
const allowedMethods = new Set(["GET", "HEAD"]);
const allowedResourceTypes = new Set([
  "document",
  "fetch",
  "font",
  "image",
  "script",
  "stylesheet",
  "xhr",
]);

class ProgramRuleRendererError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProgramRuleRendererError";
    this.code = code;
  }
}

function createProgramRuleRenderer({
  browserType = null,
  createProxy = createPinnedConnectProxy,
  now = Date.now,
  wait = defaultWait,
} = {}) {
  if (
    (browserType !== null && typeof browserType?.launch !== "function")
    || typeof createProxy !== "function"
    || typeof now !== "function"
    || typeof wait !== "function"
  ) {
    throw rendererError("program_rule_renderer_config_required");
  }

  let activeBrowser = null;
  let activeContext = null;
  let activeProxy = null;
  let cleanupPromise = null;
  let closePromise = null;
  let closing = false;
  let renderPromise = null;

  function render(input) {
    if (closing) return Promise.reject(rendererError("program_rule_renderer_closed"));
    if (renderPromise !== null) return Promise.reject(rendererError("render_in_progress"));
    const request = renderRequest(input);
    const operation = renderDocument(request);
    let tracked;
    tracked = operation.finally(() => {
      if (renderPromise === tracked) renderPromise = null;
    });
    renderPromise = tracked;
    return tracked;
  }

  function close() {
    if (closePromise !== null) return closePromise;
    closing = true;
    closePromise = (async () => {
      if (renderPromise !== null) await Promise.allSettled([renderPromise]);
      await cleanup();
    })();
    return closePromise;
  }

  async function renderDocument(request) {
    let downloadRejected = false;
    const downloadCancellations = [];
    try {
      activeProxy = await createProxy({ allowedOrigin: request.origin });
      assertProxy(activeProxy);
      assertOpen();

      const effectiveBrowserType = browserType ?? require("playwright").chromium;
      try {
        activeBrowser = await effectiveBrowserType.launch({ headless: true });
      } catch {
        throw rendererError(closing ? "program_rule_renderer_closed" : "browser_unavailable");
      }
      assertOpen();

      activeContext = await activeBrowser.newContext({
        acceptDownloads: false,
        proxy: { server: activeProxy.proxyUrl },
        serviceWorkers: "block",
      });
      assertOpen();

      let requestCount = 0;
      await activeContext.route("**/*", async (route) => {
        let allowed = false;
        try {
          const requestObject = route.request();
          requestCount += 1;
          allowed = (
            !closing
            && requestCount <= PROGRAM_RULE_RENDER_LIMITS.maxRequests
            && requestObject.redirectedFrom() === null
            && allowedMethods.has(requestObject.method())
            && allowedResourceTypes.has(requestObject.resourceType())
            && exactOrigin(requestObject.url()) === request.origin
          );
        } catch {
          allowed = false;
        }
        try {
          if (allowed) await route.continue();
          else await route.abort();
        } catch {
          // The context may close between policy evaluation and the route action.
        }
      });
      assertOpen();
      await activeContext.routeWebSocket("**/*", async (route) => {
        try {
          await route.close({ code: 1008, reason: "policy" });
        } catch {
          // The context may already be closing.
        }
      });
      assertOpen();

      const page = await activeContext.newPage();
      assertOpen();
      page.on("download", (download) => {
        downloadRejected = true;
        downloadCancellations.push(Promise.resolve().then(() => download.cancel()).catch(() => {}));
      });

      let response;
      try {
        response = await page.goto(request.url, {
          timeout: PROGRAM_RULE_RENDER_LIMITS.gotoTimeoutMs,
          waitUntil: "domcontentloaded",
        });
      } catch {
        throw rendererError(closing ? "program_rule_renderer_closed" : "fetch_failed");
      }
      await Promise.allSettled(downloadCancellations);
      if (downloadRejected) throw rendererError("download_rejected");
      assertOpen();

      const contentType = await htmlContentType(response);
      const bodyText = await stableBodyText(page.locator("body"), () => downloadRejected);
      if (downloadRejected) throw rendererError("download_rejected");
      assertOpen();

      const budget = { characters: 0 };
      const visibleStrings = boundedLines(bodyText, budget);
      const tables = await collectTables(page, budget);
      const listItems = await collectListItems(page, budget);
      const anchors = await collectAnchors(page, budget);
      if (downloadRejected) throw rendererError("download_rejected");

      return {
        document: {
          anchors,
          content_type: contentType,
          depth: request.depth,
          list_items: listItems,
          mode: "browser",
          source_url: request.url,
          tables,
          visible_strings: visibleStrings,
        },
        proxy_observed: await proxyObservation(response, activeProxy),
      };
    } catch (error) {
      throw asRendererError(error);
    } finally {
      await Promise.allSettled(downloadCancellations);
      await cleanup();
    }
  }

  async function stableBodyText(locator, isDownloadRejected) {
    let elapsed = 0;
    let previous = null;
    while (elapsed <= PROGRAM_RULE_RENDER_LIMITS.stableWindowMs) {
      assertOpen();
      if (isDownloadRejected()) throw rendererError("download_rejected");
      let current;
      try {
        current = await locator.innerText({
          timeout: Math.max(1, PROGRAM_RULE_RENDER_LIMITS.stableWindowMs - elapsed),
        });
      } catch {
        throw rendererError("fetch_failed");
      }
      if (typeof current !== "string" || current.length > PROGRAM_RULE_RENDER_LIMITS.maxBodyCharacters) {
        throw rendererError("content_rejected");
      }
      if (current === previous) return current;
      previous = current;
      if (elapsed === PROGRAM_RULE_RENDER_LIMITS.stableWindowMs) return current;
      const delay = Math.min(
        PROGRAM_RULE_RENDER_LIMITS.pollIntervalMs,
        PROGRAM_RULE_RENDER_LIMITS.stableWindowMs - elapsed,
      );
      const startedAt = now();
      await wait(delay);
      const observed = Math.max(delay, Math.floor(now() - startedAt));
      elapsed = Math.min(PROGRAM_RULE_RENDER_LIMITS.stableWindowMs, elapsed + observed);
    }
    return previous ?? "";
  }

  async function cleanup() {
    if (cleanupPromise !== null) return cleanupPromise;
    const context = activeContext;
    const browser = activeBrowser;
    const proxy = activeProxy;
    activeContext = null;
    activeBrowser = null;
    activeProxy = null;
    cleanupPromise = (async () => {
      if (context !== null) await Promise.resolve().then(() => context.close()).catch(() => {});
      if (browser !== null) await Promise.resolve().then(() => browser.close()).catch(() => {});
      if (proxy !== null) await Promise.resolve().then(() => proxy.close()).catch(() => {});
    })();
    try {
      await cleanupPromise;
    } finally {
      cleanupPromise = null;
    }
  }

  function assertOpen() {
    if (closing) throw rendererError("program_rule_renderer_closed");
  }

  return { close, render };
}

function renderRequest(value) {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).length !== 2
    || !Object.prototype.hasOwnProperty.call(value, "depth")
    || !Object.prototype.hasOwnProperty.call(value, "url")
    || ![0, 1].includes(value.depth)
  ) {
    throw rendererError("content_rejected");
  }
  let url;
  try {
    url = canonicalPublicHttpsUrl(value.url);
  } catch {
    throw rendererError("content_rejected");
  }
  return { depth: value.depth, origin: new URL(url).origin, url };
}

function assertProxy(value) {
  if (
    value === null
    || typeof value !== "object"
    || value.host !== "127.0.0.1"
    || !Number.isInteger(value.port)
    || value.port < 1
    || value.port > 65_535
    || value.proxyUrl !== `http://127.0.0.1:${value.port}`
    || typeof value.close !== "function"
  ) {
    throw rendererError("fetch_failed");
  }
}

function exactOrigin(value) {
  try {
    return new URL(canonicalPublicHttpsUrl(value)).origin;
  } catch {
    return null;
  }
}

async function htmlContentType(response) {
  if (response === null || typeof response?.headerValue !== "function") {
    throw rendererError("content_rejected");
  }
  let value;
  try {
    value = await response.headerValue("content-type");
  } catch {
    throw rendererError("content_rejected");
  }
  const normalized = typeof value === "string" ? value.split(";", 1)[0].trim().toLowerCase() : "";
  if (normalized !== "text/html") throw rendererError("content_rejected");
  return normalized;
}

async function proxyObservation(response, proxy) {
  if (typeof response?.serverAddr !== "function") return null;
  try {
    const observed = await response.serverAddr();
    if (observed === null || typeof observed !== "object") return null;
    return observed.ipAddress === proxy.host && observed.port === proxy.port;
  } catch {
    return null;
  }
}

function boundedLines(value, budget) {
  const lines = value.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean);
  return lines.map((line) => boundedProjectionText(line, budget));
}

async function collectTables(page, budget) {
  const tables = await page.locator("table").all();
  if (!Array.isArray(tables) || tables.length > PROGRAM_RULE_RENDER_LIMITS.maxTables) {
    throw rendererError("content_rejected");
  }
  const projection = [];
  for (const table of tables) {
    const rowLocators = await table.locator("tr").all();
    if (!Array.isArray(rowLocators) || rowLocators.length > 256) {
      throw rendererError("content_rejected");
    }
    const rows = [];
    for (const row of rowLocators) {
      const cells = await row.locator("th, td").allInnerTexts();
      if (!Array.isArray(cells) || cells.length > 64) throw rendererError("content_rejected");
      rows.push(cells.map((cell) => boundedProjectionText(cell, budget)));
    }
    projection.push(rows);
  }
  return projection;
}

async function collectListItems(page, budget) {
  const items = await page.locator("li").allInnerTexts();
  if (!Array.isArray(items) || items.length > PROGRAM_RULE_RENDER_LIMITS.maxListItems) {
    throw rendererError("content_rejected");
  }
  return items.map((item) => boundedProjectionText(item, budget));
}

async function collectAnchors(page, budget) {
  const locators = await page.locator("a[href]").all();
  if (!Array.isArray(locators) || locators.length > PROGRAM_RULE_RENDER_LIMITS.maxAnchors) {
    throw rendererError("content_rejected");
  }
  const anchors = [];
  for (const locator of locators) {
    const text = boundedProjectionText(await locator.innerText(), budget);
    const href = await locator.getAttribute("href");
    const download = await locator.getAttribute("download");
    if (typeof href !== "string" || href.length < 1 || href.length > 2_048) {
      throw rendererError("content_rejected");
    }
    anchors.push({ href, is_attachment: download !== null, text });
  }
  return anchors;
}

function boundedProjectionText(value, budget) {
  if (typeof value !== "string" || value.length > 8_192) {
    throw rendererError("content_rejected");
  }
  budget.characters += value.length;
  if (budget.characters > PROGRAM_RULE_RENDER_LIMITS.maxBodyCharacters) {
    throw rendererError("content_rejected");
  }
  return value;
}

function asRendererError(error) {
  return error instanceof ProgramRuleRendererError ? error : rendererError("fetch_failed");
}

function rendererError(code) {
  return new ProgramRuleRendererError(code);
}

function defaultWait(delay) {
  return new Promise((resolve) => setTimeout(resolve, delay));
}

module.exports = {
  PROGRAM_RULE_RENDER_LIMITS,
  ProgramRuleRendererError,
  createProgramRuleRenderer,
};
