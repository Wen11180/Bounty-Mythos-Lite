const assert = require("node:assert/strict");
const test = require("node:test");

const { selectStudioDirectory, selectStudioFile } = require("./path-dialog.cjs");

test("selectStudioFile returns one selected local path without reading file contents", async () => {
  const calls = [];
  const dialog = {
    async showOpenDialog(browserWindow, options) {
      calls.push({ browserWindow, options });
      return { canceled: false, filePaths: ["C:/targets/policy.md"] };
    },
  };

  const selected = await selectStudioFile(dialog, "window", {
    title: "Select policy",
  });

  assert.equal(selected, "C:/targets/policy.md");
  assert.deepEqual(calls, [
    {
      browserWindow: "window",
      options: {
        filters: [],
        properties: ["openFile"],
        title: "Select policy",
      },
    },
  ]);
});

test("selectStudioDirectory returns null when the user cancels", async () => {
  const dialog = {
    async showOpenDialog() {
      return { canceled: true, filePaths: ["C:/targets/repo"] };
    },
  };

  assert.equal(await selectStudioDirectory(dialog, "window"), null);
});

test("selectStudioDirectory opens only a directory picker", async () => {
  let capturedOptions = null;
  const dialog = {
    async showOpenDialog(_, options) {
      capturedOptions = options;
      return { canceled: false, filePaths: ["C:/targets/repo"] };
    },
  };

  assert.equal(await selectStudioDirectory(dialog, "window"), "C:/targets/repo");
  assert.deepEqual(capturedOptions, {
    properties: ["openDirectory"],
    title: "Select authorized directory",
  });
});
