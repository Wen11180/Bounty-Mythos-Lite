function isAllowedStudioNavigationUrl(targetUrl, studioUrl) {
  let target;
  let studio;
  try {
    target = new URL(targetUrl);
    studio = new URL(studioUrl);
  } catch {
    return false;
  }

  return target.origin === studio.origin;
}

function installStudioNavigationGuard(window, studioUrl) {
  window.webContents.setWindowOpenHandler(({ url }) => {
    return {
      action: isAllowedStudioNavigationUrl(url, studioUrl) ? "allow" : "deny",
    };
  });

  window.webContents.on("will-navigate", (event, url) => {
    if (!isAllowedStudioNavigationUrl(url, studioUrl)) {
      event.preventDefault();
    }
  });
}

module.exports = {
  installStudioNavigationGuard,
  isAllowedStudioNavigationUrl,
};
