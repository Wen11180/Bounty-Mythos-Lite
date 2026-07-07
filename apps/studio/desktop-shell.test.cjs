const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");

test("desktop window keeps Node isolated while loading the preload bridge", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /contextIsolation:\s*true/);
  assert.match(main, /nodeIntegration:\s*false/);
  assert.match(main, /preload:\s*path\.join\(__dirname,\s*"preload\.cjs"\)/);
});

test("preload exposes only limited Mythos Studio path picker methods", async () => {
  const preload = await fs.readFile(path.join(__dirname, "preload.cjs"), "utf8");

  assert.match(preload, /contextBridge\.exposeInMainWorld\("mythosStudio"/);
  assert.match(preload, /selectFile/);
  assert.match(preload, /selectDirectory/);
  assert.match(preload, /ipcRenderer\.invoke\("mythos:select-file"/);
  assert.match(preload, /ipcRenderer\.invoke\("mythos:select-directory"/);
  assert.doesNotMatch(preload, /readFile|writeFile|exec|spawn/);
});

test("main process registers file and directory picker IPC handlers", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /ipcMain\.handle\("mythos:select-file"/);
  assert.match(main, /ipcMain\.handle\("mythos:select-directory"/);
  assert.match(main, /selectStudioFile/);
  assert.match(main, /selectStudioDirectory/);
});
