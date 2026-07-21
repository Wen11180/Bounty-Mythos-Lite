const assert = require("node:assert/strict");
const test = require("node:test");

const {
  confirmDesktopRestore,
  selectDesktopBackupDestination,
  selectDesktopRestoreArchive,
  selectStudioDirectory,
  selectStudioFile,
} = require("./path-dialog.cjs");

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

test("desktop backup dialog returns a portable backup suffix", async () => {
  let options;
  const dialog = {
    async showSaveDialog(_window, value) {
      options = value;
      return { canceled: false, filePath: "C:/backups/personal" };
    },
  };

  const selected = await selectDesktopBackupDestination(dialog, "window");

  assert.equal(selected, "C:/backups/personal.mythos-backup.zip");
  assert.equal(options.title, "Create Mythos backup");
  assert.deepEqual(options.filters, [{ name: "Mythos backup", extensions: ["zip"] }]);
});

test("desktop restore selects one ZIP and requires explicit confirmation", async () => {
  const calls = [];
  const dialog = {
    async showMessageBox(_window, options) {
      calls.push({ kind: "confirm", options });
      return { response: 1 };
    },
    async showOpenDialog(_window, options) {
      calls.push({ kind: "open", options });
      return { canceled: false, filePaths: ["C:/backups/personal.mythos-backup.zip"] };
    },
  };

  const archive = await selectDesktopRestoreArchive(dialog, "window");
  const confirmed = await confirmDesktopRestore(dialog, "window", archive);

  assert.equal(archive, "C:/backups/personal.mythos-backup.zip");
  assert.equal(confirmed, true);
  assert.deepEqual(calls[0].options.filters, [
    { name: "Mythos backup", extensions: ["zip"] },
  ]);
  assert.equal(calls[1].options.cancelId, 0);
  assert.equal(calls[1].options.defaultId, 0);
  assert.deepEqual(calls[1].options.buttons, ["Cancel", "Restore"]);
});
