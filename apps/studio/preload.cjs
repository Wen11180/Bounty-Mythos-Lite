const { contextBridge, ipcRenderer } = require("electron");
const { apiBaseUrlFromArguments } = require("./runtime-origin.cjs");

function invokeBlackBoxRunner(operation, payload = {}) {
  const line = `${JSON.stringify({ operation, payload })}\n`;
  return ipcRenderer.invoke("mythos:black-box-runner", line);
}

contextBridge.exposeInMainWorld("mythosStudio", {
  apiBaseUrl: apiBaseUrlFromArguments(process.argv),
  createBackup() {
    return ipcRenderer.invoke("mythos:create-backup");
  },
  createBlackBoxSessions(payload) {
    return invokeBlackBoxRunner("create_sessions", payload);
  },
  startBlackBoxRecording(payload) {
    return invokeBlackBoxRunner("start_recording", payload);
  },
  stopBlackBoxRecording() {
    return invokeBlackBoxRunner("stop_recording");
  },
  runBlackBoxTrial(payload) {
    return invokeBlackBoxRunner("run_trial", payload);
  },
  closeBlackBoxSessions() {
    return invokeBlackBoxRunner("close_sessions");
  },
  refreshProgramRules() {
    return ipcRenderer.invoke("mythos:refresh-program-rules");
  },
  restoreBackup() {
    return ipcRenderer.invoke("mythos:restore-backup");
  },
  selectDirectory(options) {
    return ipcRenderer.invoke("mythos:select-directory", options);
  },
  selectFile(options) {
    return ipcRenderer.invoke("mythos:select-file", options);
  },
});
