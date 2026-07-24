const argumentPrefix = "--mythos-api-base-url=";
const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

function apiBaseUrlFromArguments(argv) {
  const argument = argv.find((value) => value.startsWith(argumentPrefix));
  if (!argument) {
    return null;
  }
  try {
    const url = new URL(argument.slice(argumentPrefix.length));
    if (
      url.protocol !== "http:"
      || !loopbackHosts.has(url.hostname)
      || !url.port
      || url.username
      || url.password
      || url.pathname !== "/"
      || url.search
      || url.hash
    ) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

module.exports = { apiBaseUrlFromArguments };
