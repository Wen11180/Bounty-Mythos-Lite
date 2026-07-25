async function selectStudioFile(dialog, browserWindow, options = {}) {
  const result = await dialog.showOpenDialog(browserWindow, {
    filters: options.filters ?? [],
    properties: ["openFile"],
    title: options.title ?? "选择授权资料",
  });
  return selectedPath(result);
}

async function selectStudioDirectory(dialog, browserWindow, options = {}) {
  const result = await dialog.showOpenDialog(browserWindow, {
    properties: ["openDirectory"],
    title: options.title ?? "选择授权目录",
  });
  return selectedPath(result);
}

async function selectDesktopBackupDestination(dialog, browserWindow) {
  const result = await dialog.showSaveDialog(browserWindow, {
    defaultPath: "mythos-backup.mythos-backup.zip",
    filters: [{ name: "研究工作台备份", extensions: ["zip"] }],
    title: "创建研究工作台备份",
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
    filters: [{ name: "研究工作台备份", extensions: ["zip"] }],
    title: "选择研究工作台备份",
  });
}

async function confirmDesktopRestore(dialog, browserWindow, archive) {
  if (!archive) {
    return false;
  }
  const result = await dialog.showMessageBox(browserWindow, {
    buttons: ["取消", "恢复"],
    cancelId: 0,
    defaultId: 0,
    message: "要恢复此本地研究工作台备份吗？",
    title: "恢复研究工作台备份",
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
