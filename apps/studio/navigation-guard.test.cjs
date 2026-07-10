const assert = require("node:assert/strict");
const test = require("node:test");

const {
  installStudioNavigationGuard,
  isAllowedStudioNavigationUrl,
} = require("./navigation-guard.cjs");

test("local Studio navigation guard allows only the configured Studio origin", () => {
  const studioUrl = "http://127.0.0.1:3000/studio";

  assert.equal(
    isAllowedStudioNavigationUrl("http://127.0.0.1:3000/studio", studioUrl),
    true,
  );
  assert.equal(
    isAllowedStudioNavigationUrl("http://127.0.0.1:3000/campaigns", studioUrl),
    true,
  );
  assert.equal(
    isAllowedStudioNavigationUrl("http://127.0.0.1:3001/studio", studioUrl),
    false,
  );
  assert.equal(
    isAllowedStudioNavigationUrl("https://example.com/program", studioUrl),
    false,
  );
  assert.equal(
    isAllowedStudioNavigationUrl("file:///C:/targets/policy.md", studioUrl),
    false,
  );
});

test("local Studio navigation guard rejects data documents after Studio starts", () => {
  assert.equal(
    isAllowedStudioNavigationUrl(
      "data:text/html,%3Ch1%3EStartup%20failed%3C%2Fh1%3E",
      "http://127.0.0.1:3000/studio",
    ),
    false,
  );
  assert.equal(
    isAllowedStudioNavigationUrl(
      "data:application/json,%7B%7D",
      "http://127.0.0.1:3000/studio",
    ),
    false,
  );
});

test("installStudioNavigationGuard denies external windows and prevents external navigation", () => {
  const handlers = {};
  const window = {
    webContents: {
      on(eventName, handler) {
        handlers[eventName] = handler;
      },
      setWindowOpenHandler(handler) {
        handlers.windowOpen = handler;
      },
    },
  };

  installStudioNavigationGuard(window, "http://127.0.0.1:3000/studio");

  assert.deepEqual(
    handlers.windowOpen({ url: "http://127.0.0.1:3000/studio" }),
    { action: "allow" },
  );
  assert.deepEqual(
    handlers.windowOpen({ url: "https://example.com" }),
    { action: "deny" },
  );

  let prevented = false;
  handlers["will-navigate"](
    {
      preventDefault() {
        prevented = true;
      },
    },
    "https://example.com",
  );
  assert.equal(prevented, true);

  prevented = false;
  handlers["will-navigate"](
    {
      preventDefault() {
        prevented = true;
      },
    },
    "http://127.0.0.1:3000/studio",
  );
  assert.equal(prevented, false);
});
