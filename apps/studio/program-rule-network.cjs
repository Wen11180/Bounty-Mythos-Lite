const { createHash } = require("node:crypto");
const dns = require("node:dns");
const https = require("node:https");
const net = require("node:net");
const { performance } = require("node:perf_hooks");

const ipaddr = require("ipaddr.js");

const PROGRAM_RULE_NETWORK_LIMITS = Object.freeze({
  connectTimeoutMs: 10_000,
  maxAggregateBytes: 8 * 1024 * 1024,
  maxDocumentBytes: 2 * 1024 * 1024,
  maxDocuments: 8,
  maxHeaderBytes: 16 * 1024,
  maxRequests: 32,
  maxTunnelBytes: 8 * 1024 * 1024,
  timeoutMs: 10_000,
});

const acceptedContentTypes = new Set([
  "application/json",
  "application/x-yaml",
  "application/yaml",
  "text/html",
  "text/plain",
  "text/yaml",
]);
const acceptedMethods = new Set(["GET", "HEAD"]);
const secretQueryKeys = new Set([
  "accesskey",
  "accesskeyid",
  "accesstoken",
  "apikey",
  "authorization",
  "authtoken",
  "cookie",
  "credential",
  "jwt",
  "password",
  "secret",
  "session",
  "sessionid",
  "token",
]);
const secretValuePrefixes = [
  "basic ",
  "bearer ",
  "ghp_",
  "github_pat_",
  "sk-",
  "xoxb-",
  "xoxp-",
];
const jwtPattern = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}$/u;

class ProgramRuleNetworkError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProgramRuleNetworkError";
    this.code = code;
  }
}

function canonicalPublicHttpsUrl(value) {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > 2048
    || value.includes("#")
    || value.includes("\\")
    || /[\s\p{C}]/u.test(value)
  ) {
    throw networkError("content_rejected");
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw networkError("content_rejected");
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || !parsed.hostname
    || parsed.hostname.startsWith(".")
    || parsed.hostname.endsWith(".")
    || parsed.hostname.includes("..")
    || !isCanonicalUrlHostname(parsed.hostname)
    || parsed.port === "0"
    || parsed.href !== value
  ) {
    throw networkError("content_rejected");
  }
  for (const [key, queryValue] of parsed.searchParams) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
    const loweredValue = queryValue.toLowerCase();
    if (
      secretQueryKeys.has(normalizedKey)
      || secretValuePrefixes.some((prefix) => loweredValue.startsWith(prefix))
      || jwtPattern.test(queryValue)
    ) {
      throw networkError("content_rejected");
    }
  }
  return parsed.href;
}

function isGloballyRoutableAddress(address) {
  try {
    return ipaddr.process(address).range() === "unicast";
  } catch {
    return false;
  }
}

async function resolvePinnedPublicAddress(hostname, dependencies = {}) {
  const lookup = dependencies.lookup ?? dns.promises.lookup;
  const classifyAddress = dependencies.classifyAddress ?? isGloballyRoutableAddress;
  if (
    typeof lookup !== "function"
    || typeof classifyAddress !== "function"
    || !isLookupHostname(hostname)
  ) {
    throw networkError("dns_rejected");
  }
  let answers;
  try {
    answers = await withTimeout(
      Promise.resolve().then(() => lookup(hostname, { all: true, order: "verbatim" })),
      narrowedLimit(dependencies.timeoutMs, PROGRAM_RULE_NETWORK_LIMITS.timeoutMs),
      "dns_rejected",
    );
  } catch {
    throw networkError("dns_rejected");
  }
  if (!Array.isArray(answers) || answers.length === 0) {
    throw networkError("dns_rejected");
  }
  const normalized = [];
  for (const answer of answers) {
    try {
      const raw = ipaddr.parse(answer?.address);
      const rawFamily = raw.kind() === "ipv4" ? 4 : 6;
      const parsed = normalizeAddress(answer?.address);
      const family = parsed.kind() === "ipv4" ? 4 : 6;
      const address = parsed.toString();
      if (answer?.family !== rawFamily || classifyAddress(address) !== true) {
        throw networkError("dns_rejected");
      }
      normalized.push({ address, family });
    } catch {
      throw networkError("dns_rejected");
    }
  }
  normalized.sort((left, right) => (
    left.family - right.family || left.address.localeCompare(right.address)
  ));
  return normalized[0];
}

async function fetchPublicRuleDocument(request, dependencies = {}) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    throw networkError("content_rejected");
  }
  const url = canonicalPublicHttpsUrl(request.url);
  const allowed = canonicalPublicHttpsOrigin(request.allowedOrigin);
  const parsed = new URL(url);
  const method = request.method;
  if (!acceptedMethods.has(method) || parsed.origin !== allowed.origin) {
    throw networkError("content_rejected");
  }
  const documentCount = boundedUsage(
    request.documentCount,
    PROGRAM_RULE_NETWORK_LIMITS.maxDocuments,
  );
  const aggregateBytes = boundedUsage(
    request.aggregateBytes,
    PROGRAM_RULE_NETWORK_LIMITS.maxAggregateBytes,
  );
  if (
    documentCount >= PROGRAM_RULE_NETWORK_LIMITS.maxDocuments
    || aggregateBytes >= PROGRAM_RULE_NETWORK_LIMITS.maxAggregateBytes
  ) {
    throw networkError("budget_exceeded");
  }

  const hostname = hostnameForLookup(parsed.hostname);
  const timeoutMs = narrowedLimit(
    dependencies.timeoutMs,
    PROGRAM_RULE_NETWORK_LIMITS.timeoutMs,
  );
  const startedAt = performance.now();
  const pinned = await resolvePinnedPublicAddress(hostname, {
    ...dependencies,
    timeoutMs,
  });
  const remainingTimeoutMs = Math.floor(timeoutMs - (performance.now() - startedAt));
  if (remainingTimeoutMs < 1) throw networkError("budget_exceeded");
  const httpsRequest = dependencies.httpsRequest ?? https.request;
  if (typeof httpsRequest !== "function") {
    throw networkError("fetch_failed");
  }

  const options = {
    agent: false,
    autoSelectFamily: false,
    family: pinned.family,
    headers: {
      accept: [
        "text/html",
        "text/plain",
        "application/json",
        "application/yaml",
        "application/x-yaml",
        "text/yaml",
      ].join(", "),
      "accept-encoding": "identity",
    },
    hostname,
    lookup(requestedHostname, _options, callback) {
      if (requestedHostname !== hostname) {
        callback(networkError("dns_rejected"));
        return;
      }
      callback(null, pinned.address, pinned.family);
    },
    method,
    path: `${parsed.pathname}${parsed.search}`,
    port: Number(parsed.port || 443),
    protocol: "https:",
    rejectUnauthorized: true,
    ...(net.isIP(hostname) === 0 ? { servername: hostname } : {}),
  };

  return new Promise((resolve, reject) => {
    let clientRequest;
    let response;
    let settled = false;
    let peerVerified = false;

    const finishError = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(asNetworkError(error, "fetch_failed"));
    };
    const abort = (code) => {
      if (settled) return;
      const error = networkError(code);
      response?.destroy();
      clientRequest?.destroy();
      finishError(error);
    };
    const timer = setTimeout(() => abort("budget_exceeded"), remainingTimeoutMs);

    try {
      clientRequest = httpsRequest(options, (incoming) => {
        response = incoming;
        if (settled) {
          response.destroy();
          return;
        }
        if (!peerVerified) {
          abort("dns_rejected");
          return;
        }
        const statusCode = Number(response.statusCode ?? 0);
        if (statusCode >= 300 && statusCode < 400) {
          abort("redirect_rejected");
          return;
        }
        if (statusCode < 200 || statusCode >= 300) {
          abort("fetch_failed");
          return;
        }
        const rawContentEncoding = response.headers?.["content-encoding"];
        const contentEncoding = singleHeader(rawContentEncoding);
        if (
          rawContentEncoding !== undefined
          && (contentEncoding === null || contentEncoding.toLowerCase() !== "identity")
        ) {
          abort("content_rejected");
          return;
        }
        const contentTypeHeader = singleHeader(response.headers?.["content-type"]);
        const contentType = contentTypeHeader?.split(";", 1)[0].trim().toLowerCase();
        if (!contentType || !acceptedContentTypes.has(contentType)) {
          abort("content_rejected");
          return;
        }
        const declaredLength = contentLength(response.headers?.["content-length"]);
        if (
          declaredLength === null
          && response.headers?.["content-length"] !== undefined
        ) {
          abort("content_rejected");
          return;
        }
        if (
          declaredLength !== null
          && (
            declaredLength > PROGRAM_RULE_NETWORK_LIMITS.maxDocumentBytes
            || aggregateBytes + declaredLength > PROGRAM_RULE_NETWORK_LIMITS.maxAggregateBytes
          )
        ) {
          abort("budget_exceeded");
          return;
        }

        const chunks = [];
        const digest = createHash("sha256");
        let byteLength = 0;
        response.on("data", (chunk) => {
          if (settled) return;
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          byteLength += bytes.length;
          if (
            (method === "HEAD" && byteLength > 0)
            || byteLength > PROGRAM_RULE_NETWORK_LIMITS.maxDocumentBytes
            || aggregateBytes + byteLength > PROGRAM_RULE_NETWORK_LIMITS.maxAggregateBytes
          ) {
            abort("budget_exceeded");
            return;
          }
          chunks.push(bytes);
          digest.update(bytes);
        });
        response.once("aborted", () => finishError(networkError("fetch_failed")));
        response.once("error", () => finishError(networkError("fetch_failed")));
        response.once("end", () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          const body = Buffer.concat(chunks, byteLength);
          resolve({
            aggregateBytes: aggregateBytes + byteLength,
            bodyBase64: body.toString("base64"),
            byteLength,
            contentType,
            documentCount: documentCount + 1,
            method,
            peerVerified: true,
            rawSha256: digest.digest("hex"),
            statusCode,
            url,
          });
        });
      });
    } catch {
      finishError(networkError("fetch_failed"));
      return;
    }

    clientRequest.once("socket", (socket) => {
      const verify = () => {
        try {
          const remoteAddress = normalizeAddress(socket.remoteAddress).toString();
          if (remoteAddress !== pinned.address) {
            abort("dns_rejected");
            return;
          }
          peerVerified = true;
        } catch {
          abort("dns_rejected");
        }
      };
      if (socket.connecting) socket.once("connect", verify);
      else verify();
    });
    clientRequest.once("error", (error) => finishError(error));
    clientRequest.end();
  });
}

async function createPinnedConnectProxy({
  allowedOrigin,
  dependencies = {},
  limits = {},
} = {}) {
  const allowed = canonicalPublicHttpsOrigin(allowedOrigin);
  const effectiveLimits = proxyLimits(limits);
  const createServer = dependencies.createServer ?? net.createServer;
  const connect = dependencies.connect ?? net.connect;
  if (typeof createServer !== "function" || typeof connect !== "function") {
    throw networkError("fetch_failed");
  }

  const clients = new Set();
  const upstreams = new Set();
  const pending = new Set();
  let closing = false;
  let closePromise = null;
  let requestCount = 0;
  let tunnelBytes = 0;

  const server = createServer({ pauseOnConnect: true }, (socket) => {
    clients.add(socket);
    socket.once("close", () => clients.delete(socket));
    socket.on("error", () => socket.destroy());
    if (closing) {
      socket.destroy();
      return;
    }
    requestCount += 1;
    if (requestCount > effectiveLimits.maxRequests) {
      rejectProxyClient(socket, 503, "Service Unavailable");
      return;
    }

    let buffered = Buffer.alloc(0);
    const headerTimer = setTimeout(
      () => socket.destroy(),
      effectiveLimits.connectTimeoutMs,
    );
    socket.once("close", () => clearTimeout(headerTimer));
    const onHeaderData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length > effectiveLimits.maxHeaderBytes) {
        clearTimeout(headerTimer);
        socket.off("data", onHeaderData);
        rejectProxyClient(socket, 431, "Request Header Fields Too Large");
        return;
      }
      const headerEnd = buffered.indexOf("\r\n\r\n");
      if (headerEnd === -1) return;
      clearTimeout(headerTimer);
      socket.off("data", onHeaderData);
      const extra = buffered.subarray(headerEnd + 4);
      const authority = parseConnectRequest(
        buffered.subarray(0, headerEnd + 4).toString("latin1"),
        allowed,
      );
      if (authority === null || extra.length !== 0) {
        rejectProxyClient(socket, 400, "Bad Request");
        return;
      }
      let earlyData = false;
      let earlyDataGuardReleased = false;
      const onEarlyData = () => {
        earlyData = true;
        socket.destroy();
      };
      socket.on("data", onEarlyData);
      const releaseEarlyDataGuard = () => {
        if (!earlyDataGuardReleased) {
          earlyDataGuardReleased = true;
          socket.off("data", onEarlyData);
        }
        return !earlyData && !socket.destroyed;
      };
      const operation = establishTunnel({
        allowed,
        classifyAddress: dependencies.classifyAddress,
        connect,
        limits: effectiveLimits,
        lookup: dependencies.lookup,
        onBytes(length) {
          tunnelBytes += length;
          return tunnelBytes <= effectiveLimits.maxTunnelBytes;
        },
        releaseEarlyDataGuard,
        socket,
        upstreams,
      }).finally(() => pending.delete(operation));
      pending.add(operation);
    };
    socket.on("data", onHeaderData);
    socket.resume();
  });

  await new Promise((resolve, reject) => {
    const onError = () => reject(networkError("fetch_failed"));
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string" || address.address !== "127.0.0.1") {
    server.close();
    throw networkError("fetch_failed");
  }
  server.on("error", () => {
    for (const socket of [...clients, ...upstreams]) socket.destroy();
  });

  return {
    host: "127.0.0.1",
    port: address.port,
    proxyUrl: `http://127.0.0.1:${address.port}`,
    close() {
      if (closePromise !== null) return closePromise;
      closePromise = (async () => {
        closing = true;
        const serverClosed = new Promise((resolve) => {
          if (!server.listening) {
            resolve();
            return;
          }
          server.close(() => resolve());
        });
        for (const socket of [...clients, ...upstreams]) socket.destroy();
        await Promise.allSettled([...pending]);
        for (const socket of [...clients, ...upstreams]) socket.destroy();
        await serverClosed;
      })();
      return closePromise;
    },
  };
}

async function establishTunnel({
  allowed,
  classifyAddress,
  connect,
  limits,
  lookup,
  onBytes,
  releaseEarlyDataGuard,
  socket,
  upstreams,
}) {
  let pinned;
  try {
    pinned = await resolvePinnedPublicAddress(allowed.hostname, {
      classifyAddress,
      lookup,
      timeoutMs: limits.connectTimeoutMs,
    });
  } catch {
    releaseEarlyDataGuard();
    rejectProxyClient(socket, 502, "Bad Gateway");
    return;
  }
  if (socket.destroyed) {
    releaseEarlyDataGuard();
    return;
  }

  await new Promise((resolve) => {
    let established = false;
    let upstream;
    try {
      upstream = connect({
        family: pinned.family,
        host: pinned.address,
        port: allowed.port,
      });
    } catch {
      releaseEarlyDataGuard();
      rejectProxyClient(socket, 502, "Bad Gateway");
      resolve();
      return;
    }
    upstreams.add(upstream);
    upstream.once("close", () => {
      releaseEarlyDataGuard();
      upstreams.delete(upstream);
      socket.destroy();
      resolve();
    });
    upstream.on("error", () => {
      if (!established) rejectProxyClient(socket, 502, "Bad Gateway");
      upstream.destroy();
    });
    upstream.setTimeout(limits.connectTimeoutMs, () => upstream.destroy());
    upstream.once("connect", () => {
      upstream.setTimeout(0);
      let remoteAddress;
      try {
        remoteAddress = normalizeAddress(upstream.remoteAddress).toString();
      } catch {
        releaseEarlyDataGuard();
        upstream.destroy();
        return;
      }
      if (remoteAddress !== pinned.address) {
        releaseEarlyDataGuard();
        upstream.destroy();
        return;
      }
      if (!releaseEarlyDataGuard()) {
        upstream.destroy();
        return;
      }
      established = true;
      const forward = (source, destination) => (chunk) => {
        if (!onBytes(chunk.length)) {
          socket.destroy();
          upstream.destroy();
          return;
        }
        if (!destination.write(chunk)) {
          source.pause();
          destination.once("drain", () => {
            if (!source.destroyed && !destination.destroyed) source.resume();
          });
        }
      };
      socket.on("data", forward(socket, upstream));
      upstream.on("data", forward(upstream, socket));
      socket.once("end", () => upstream.end());
      upstream.once("end", () => socket.end());
      socket.once("close", () => upstream.destroy());
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      socket.resume();
      resolve();
    });
  });
}

function parseConnectRequest(header, allowed) {
  const lines = header.slice(0, -4).split("\r\n");
  const requestLine = /^CONNECT ([^ ]+) HTTP\/1\.1$/u.exec(lines.shift() ?? "");
  if (!requestLine || requestLine[1] !== allowed.authority) return null;
  const headers = new Map();
  for (const line of lines) {
    const parsed = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*)$/u.exec(line);
    if (!parsed) return null;
    const name = parsed[1].toLowerCase();
    if (headers.has(name)) return null;
    headers.set(name, parsed[2]);
  }
  if (
    headers.has("authorization")
    || headers.has("cookie")
    || headers.has("content-length")
    || headers.has("proxy-authorization")
    || headers.has("transfer-encoding")
    || headers.has("via")
    || headers.has("forwarded")
  ) {
    return null;
  }
  const host = headers.get("host");
  if (host !== allowed.authority) return null;
  return requestLine[1];
}

function canonicalPublicHttpsOrigin(value) {
  if (typeof value !== "string") throw networkError("content_rejected");
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw networkError("content_rejected");
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || parsed.port === "0"
    || !isCanonicalUrlHostname(parsed.hostname)
    || parsed.origin !== value
  ) {
    throw networkError("content_rejected");
  }
  const hostname = hostnameForLookup(parsed.hostname);
  if (!isLookupHostname(hostname)) throw networkError("content_rejected");
  const port = Number(parsed.port || 443);
  return {
    authority: connectAuthority(parsed.hostname, port),
    hostname,
    origin: parsed.origin,
    port,
  };
}

function connectAuthority(urlHostname, port) {
  return `${urlHostname}:${port}`;
}

function proxyLimits(limits) {
  if (!limits || typeof limits !== "object" || Array.isArray(limits)) {
    throw networkError("content_rejected");
  }
  const known = new Set([
    "connectTimeoutMs",
    "maxHeaderBytes",
    "maxRequests",
    "maxTunnelBytes",
  ]);
  if (Object.keys(limits).some((key) => !known.has(key))) {
    throw networkError("content_rejected");
  }
  return {
    connectTimeoutMs: narrowedLimit(
      limits.connectTimeoutMs,
      PROGRAM_RULE_NETWORK_LIMITS.connectTimeoutMs,
    ),
    maxHeaderBytes: narrowedLimit(
      limits.maxHeaderBytes,
      PROGRAM_RULE_NETWORK_LIMITS.maxHeaderBytes,
    ),
    maxRequests: narrowedLimit(
      limits.maxRequests,
      PROGRAM_RULE_NETWORK_LIMITS.maxRequests,
    ),
    maxTunnelBytes: narrowedLimit(
      limits.maxTunnelBytes,
      PROGRAM_RULE_NETWORK_LIMITS.maxTunnelBytes,
    ),
  };
}

function rejectProxyClient(socket, status, reason) {
  if (socket.destroyed) return;
  socket.end(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`);
}

function boundedUsage(value, ceiling) {
  if (!Number.isSafeInteger(value) || value < 0 || value > ceiling) {
    throw networkError("budget_exceeded");
  }
  return value;
}

function narrowedLimit(value, maximum) {
  if (value === undefined) return maximum;
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw networkError("content_rejected");
  }
  return value;
}

function singleHeader(value) {
  if (value === undefined) return null;
  return typeof value === "string" ? value.trim() : null;
}

function contentLength(value) {
  if (value === undefined) return null;
  const normalized = singleHeader(value);
  if (!normalized || !/^(?:0|[1-9][0-9]*)$/u.test(normalized)) return null;
  const parsed = Number(normalized);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function hostnameForLookup(value) {
  if (value.startsWith("[") && value.endsWith("]")) return value.slice(1, -1);
  return value;
}

function isCanonicalUrlHostname(value) {
  const hostname = hostnameForLookup(value);
  if (net.isIP(hostname) !== 0) return true;
  return (
    hostname.length <= 253
    && hostname.includes(".")
    && hostname.split(".").every((label) => (
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label)
    ))
  );
}

function isLookupHostname(value) {
  return (
    typeof value === "string"
    && value.length > 0
    && value.length <= 253
    && !/[\s/\\?#@]/u.test(value)
    && isCanonicalUrlHostname(value)
  );
}

function normalizeAddress(value) {
  return ipaddr.process(value);
}

function asNetworkError(error, fallback) {
  return error instanceof ProgramRuleNetworkError ? error : networkError(fallback);
}

function withTimeout(promise, timeoutMs, code) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(networkError(code)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        reject(networkError(code));
      },
    );
  });
}

function networkError(code) {
  return new ProgramRuleNetworkError(code);
}

module.exports = {
  PROGRAM_RULE_NETWORK_LIMITS,
  ProgramRuleNetworkError,
  canonicalPublicHttpsUrl,
  createPinnedConnectProxy,
  fetchPublicRuleDocument,
  isGloballyRoutableAddress,
  resolvePinnedPublicAddress,
};
