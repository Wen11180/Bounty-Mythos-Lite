async function selectStudioFile(dialog, browserWindow, options = {}) {
  const result = await dialog.showOpenDialog(browserWindow, {
    filters: options.filters ?? [],
    properties: ["openFile"],
    title: options.title ?? "Select authorized artifact",
  });
  return selectedPath(result);
}

async function selectStudioDirectory(dialog, browserWindow, options = {}) {
  const result = await dialog.showOpenDialog(browserWindow, {
    properties: ["openDirectory"],
    title: options.title ?? "Select authorized directory",
  });
  return selectedPath(result);
}

async function selectDesktopBackupDestination(dialog, browserWindow) {
  const result = await dialog.showSaveDialog(browserWindow, {
    defaultPath: "mythos-backup.mythos-backup.zip",
    filters: [{ name: "Mythos backup", extensions: ["zip"] }],
    title: "Create Mythos backup",
  });
  if (result.canceled || !result.filePath) {
    return null;
  }
  return result.filePath.toLowerCase().endsWith(".mythos-backup.zip")
    ? result.filePath
    : `${result.filePath}.mythos-backup.zip`;
}

async function selectDesktopRestoreArchive(dialog, browserWindow) {
  return selectStudioFile(dialog, browserWindow, {
    filters: [{ name: "Mythos backup", extensions: ["zip"] }],
    title: "Select Mythos backup",
  });
}

async function confirmDesktopRestore(dialog, browserWindow, archive) {
  if (!archive) {
    return false;
  }
  const result = await dialog.showMessageBox(browserWindow, {
    buttons: ["Cancel", "Restore"],
    cancelId: 0,
    defaultId: 0,
    message: "Restore this local Mythos backup?",
    title: "Restore Mythos backup",
    type: "warning",
  });
  return result.response === 1;
}

function selectedPath(result) {
  if (result.canceled || !Array.isArray(result.filePaths) || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0] || null;
}

module.exports = {
  confirmDesktopRestore,
  selectDesktopBackupDestination,
  selectDesktopRestoreArchive,
  selectStudioDirectory,
  selectStudioFile,
};
