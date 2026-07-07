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

function selectedPath(result) {
  if (result.canceled || !Array.isArray(result.filePaths) || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0] || null;
}

module.exports = {
  selectStudioDirectory,
  selectStudioFile,
};
