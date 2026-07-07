const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("mythosStudio", {
  selectDirectory(options) {
    return ipcRenderer.invoke("mythos:select-directory", options);
  },
  selectFile(options) {
    return ipcRenderer.invoke("mythos:select-file", options);
  },
});
