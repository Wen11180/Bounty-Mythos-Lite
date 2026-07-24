const assert = require("node:assert/strict");
const { createPrivateKey, X509Certificate } = require("node:crypto");
const { EventEmitter, once } = require("node:events");
const https = require("node:https");
const net = require("node:net");
const { PassThrough } = require("node:stream");
const test = require("node:test");

const {
  PROGRAM_RULE_NETWORK_LIMITS,
  canonicalPublicHttpsUrl,
  createPinnedConnectProxy,
  fetchPublicRuleDocument,
  isGloballyRoutableAddress,
  resolvePinnedPublicAddress,
} = require("./program-rule-network.cjs");

const PUBLIC_IPV4 = "93.184.216.34";
const PUBLIC_IPV6 = "2606:4700:4700::1111";
// Static DER values are synthetic and usable only by this loopback test fixture.
const FIXTURE_KEY = createPrivateKey({
  format: "der",
  key: Buffer.from(
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyIFhnVrZw3U+CIVGjbVk1iVBPFjlitHIl6JR4Z7Oo6+hRANCAASH9CheQ1ZnvnnmqvD0VXzojFmz8VNn6jJGYaJZw54qIJgSybndB7/5uLFw8wSXqqZDohHfA4tZPl818nfOvZeN",
    "base64",
  ),
  type: "pkcs8",
}).export({ format: "pem", type: "pkcs8" });
const FIXTURE_CERT = new X509Certificate(Buffer.from(
  "MIIBYDCCAQegAwIBAgIBATAKBggqhkjOPQQDAjAfMR0wGwYDVQQDDBRmaXh0dXJlLmV4YW1wbGUudGVzdDAeFw0yNTAxMDEwMDAwMDBaFw00NTAxMDEwMDAwMDBaMB8xHTAbBgNVBAMMFGZpeHR1cmUuZXhhbXBsZS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh/QoXkNWZ7555qrw9FV86IxZs/FTZ+oyRmGiWcOeKiCYEsm53Qe/+bixcPMEl6qmQ6IR3wOLWT5fNfJ3zr2XjaM0MDIwHwYDVR0RBBgwFoIUZml4dHVyZS5leGFtcGxlLnRlc3QwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiA7K1TPSejPHYS2RWccAVzZtRjULkIuwqmCsJdE39zL+wIgCI3vjAHR/qfpx4c+Rmdfwbgo8Zsb348T7Yn+04CS6Ng=",
  "base64",
)).toString();

test("canonical public URLs reject alternate syntax, credentials, fragments, and secrets", () => {
  const canonical = "https://rules.example.test/program?view=scope";
  assert.equal(canonicalPublicHttpsUrl(canonical), canonical);
  assert.equal(
    canonicalPublicHttpsUrl("https://[2606:4700:4700::1111]/rules"),
    "https://[2606:4700:4700::1111]/rules",
  );

  for (const value of [
    "http://rules.example.test/program",
    "https://RULES.example.test/program",
    "https://rules.example.test:443/program",
    "https://rules.example.test",
    "https://user:pass@rules.example.test/program",
    "https://rules.example.test/program#scope",
    "https://rules.example.test/program?access_token=public-looking",
    "https://rules.example.test/program?value=Bearer%20example",
    "https://rules.example.test/program?value=eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb",
    "https://rules.example.test:0/program",
    "https://bad_host.example.test/program",
    "https://localhost/",
    "https://intranet/",
    " https://rules.example.test/program",
    "https://rules.example.test\\program",
  ]) {
    assert.throws(
      () => canonicalPublicHttpsUrl(value),
      (error) => error.code === "content_rejected" && error.message === "content_rejected",
      value,
    );
  }
});

test("public address classifier rejects the special IPv4 and IPv6 corpus", () => {
  for (const address of [PUBLIC_IPV4, PUBLIC_IPV6, "1.1.1.1", "2001:4860:4860::8888"]) {
    assert.equal(isGloballyRoutableAddress(address), true, address);
  }
  for (const address of [
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "172.16.0.1",
    "192.0.2.1",
    "192.168.1.1",
    "192.88.99.1",
    "198.18.0.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "2001:db8::1",
    "64:ff9b::1",
    "2001::1",
    "2001:2::1",
    "2001:10::1",
    "2002:0808:0808::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "not-an-address",
  ]) {
    assert.equal(isGloballyRoutableAddress(address), false, address);
  }
});

test("DNS pinning validates every answer and selects deterministically", async () => {
  const calls = [];
  const resolved = await resolvePinnedPublicAddress("rules.example.test", {
    lookup: async (hostname, options) => {
      calls.push({ hostname, options });
      return [
        { address: PUBLIC_IPV6, family: 6 },
        { address: PUBLIC_IPV4, family: 4 },
      ];
    },
  });
  assert.deepEqual(calls, [{
    hostname: "rules.example.test",
    options: { all: true, order: "verbatim" },
  }]);
  assert.deepEqual(resolved, { address: PUBLIC_IPV4, family: 4 });
  assert.deepEqual(
    await resolvePinnedPublicAddress("mapped-public.example.test", {
      lookup: async () => [{ address: `::ffff:${PUBLIC_IPV4}`, family: 6 }],
    }),
    { address: PUBLIC_IPV4, family: 4 },
  );

  for (const answers of [
    [],
    [{ address: "127.0.0.1", family: 4 }],
    [
      { address: PUBLIC_IPV4, family: 4 },
      { address: "10.0.0.1", family: 4 },
    ],
    [{ address: "malformed", family: 4 }],
  ]) {
    await assert.rejects(
      resolvePinnedPublicAddress("private-answer.example.test", {
        lookup: async () => answers,
      }),
      safeError("dns_rejected", ["private-answer", "10.0.0.1", "127.0.0.1"]),
    );
  }
  await assert.rejects(
    resolvePinnedPublicAddress("lookup-error.example.test", {
      lookup: async () => {
        throw new Error("resolver leaked 10.0.0.1");
      },
    }),
    safeError("dns_rejected", ["resolver leaked", "10.0.0.1"]),
  );
  await assert.rejects(
    resolvePinnedPublicAddress("hung-dns.example.test", {
      lookup: async () => new Promise(() => {}),
      timeoutMs: 5,
    }),
    safeError("dns_rejected", ["hung-dns"]),
  );
});

test("static HTTPS fetch pins lookup, strips caller headers, and returns bounded bytes", async () => {
  const fake = createFakeHttpsRequest({
    body: ["In scope: api.example.test"],
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "set-cookie": "session=must-not-surface",
      "x-debug-secret": "header-must-not-surface",
    },
  });
  const logged = [];
  const originalLog = console.log;
  console.log = (...values) => logged.push(values);
  try {
    const result = await fetchPublicRuleDocument({
      allowedOrigin: "https://rules.example.test",
      aggregateBytes: 10,
      documentCount: 1,
      method: "GET",
      url: "https://rules.example.test/program?view=scope",
    }, {
      httpsRequest: fake.request,
      lookup: async () => [{ address: PUBLIC_IPV4, family: 4 }],
    });

    assert.equal(fake.calls.length, 1);
    const options = fake.calls[0];
    assert.equal(options.agent, false);
    assert.equal(options.rejectUnauthorized, true);
    assert.equal(options.method, "GET");
    assert.equal(options.hostname, "rules.example.test");
    assert.equal(options.servername, "rules.example.test");
    assert.equal(options.path, "/program?view=scope");
    assert.deepEqual(options.headers, {
      accept: "text/html, text/plain, application/json, application/yaml, application/x-yaml, text/yaml",
      "accept-encoding": "identity",
    });
    const lookupResult = await callPinnedLookup(options.lookup, "rules.example.test");
    assert.deepEqual(lookupResult, { address: PUBLIC_IPV4, family: 4 });
    assert.deepEqual(result, {
      aggregateBytes: 36,
      bodyBase64: Buffer.from("In scope: api.example.test").toString("base64"),
      byteLength: 26,
      contentType: "text/plain",
      documentCount: 2,
      method: "GET",
      peerVerified: true,
      rawSha256: "e8824b915f69f28e6566a84790ee9659439fdb0fb24fc895c6a81576b274f34b",
      statusCode: 200,
      url: "https://rules.example.test/program?view=scope",
    });
    assert.deepEqual(logged, []);
    const serialized = JSON.stringify(result);
    assert.doesNotMatch(serialized, /set-cookie|must-not-surface|x-debug-secret|header-must/u);
  } finally {
    console.log = originalLog;
  }
});

test("static HTTPS integration preserves certificate validation, SNI, and pinned peer", async (t) => {
  const observations = [];
  const server = https.createServer({ cert: FIXTURE_CERT, key: FIXTURE_KEY }, (request, response) => {
    observations.push({ headers: request.headers, method: request.method, url: request.url });
    response.writeHead(200, {
      "content-encoding": "identity",
      "content-type": "text/plain; charset=utf-8",
    });
    response.end("Synthetic public rule fixture");
  });
  await listen(server, "127.0.0.1");
  t.after(() => closeServer(server));
  const port = server.address().port;

  const result = await fetchPublicRuleDocument({
    aggregateBytes: 0,
    allowedOrigin: `https://fixture.example.test:${port}`,
    documentCount: 0,
    method: "GET",
    url: `https://fixture.example.test:${port}/rules`,
  }, {
    classifyAddress: (address) => address === "127.0.0.1",
    httpsRequest: (options, callback) => https.request({
      ...options,
      ca: FIXTURE_CERT,
    }, callback),
    lookup: async () => [{ address: "127.0.0.1", family: 4 }],
  });

  assert.equal(Buffer.from(result.bodyBase64, "base64").toString(), "Synthetic public rule fixture");
  assert.equal(result.peerVerified, true);
  assert.deepEqual(observations, [{
    headers: {
      accept: "text/html, text/plain, application/json, application/yaml, application/x-yaml, text/yaml",
      "accept-encoding": "identity",
      connection: "close",
      host: `fixture.example.test:${port}`,
    },
    method: "GET",
    url: "/rules",
  }]);
});

test("static HTTPS fetch maps redirects, content, peer, network, and budget failures", async () => {
  const baseRequest = {
    allowedOrigin: "https://rules.example.test",
    aggregateBytes: 0,
    documentCount: 0,
    method: "GET",
    url: "https://rules.example.test/program",
  };
  const baseDependencies = {
    lookup: async () => [{ address: PUBLIC_IPV4, family: 4 }],
  };
  const cases = [
    {
      code: "redirect_rejected",
      fake: { statusCode: 302, headers: { location: "https://secret.invalid/?token=hidden" } },
      forbidden: ["secret.invalid", "token=hidden"],
    },
    { code: "content_rejected", fake: { headers: {} } },
    { code: "content_rejected", fake: { headers: { "content-type": "application/pdf" } } },
    {
      code: "content_rejected",
      fake: { headers: { "content-encoding": "gzip", "content-type": "text/plain" } },
    },
    {
      code: "content_rejected",
      fake: { headers: { "content-encoding": ["identity"], "content-type": "text/plain" } },
    },
    {
      code: "dns_rejected",
      fake: { remoteAddress: "93.184.216.35" },
      forbidden: ["93.184.216.35"],
    },
    {
      code: "budget_exceeded",
      fake: { body: [Buffer.alloc(PROGRAM_RULE_NETWORK_LIMITS.maxDocumentBytes + 1)] },
    },
    {
      code: "budget_exceeded",
      fake: {
        headers: {
          "content-length": String(PROGRAM_RULE_NETWORK_LIMITS.maxDocumentBytes + 1),
          "content-type": "text/plain",
        },
      },
    },
    {
      code: "fetch_failed",
      fake: { networkError: new Error("socket leaked Authorization: Bearer hidden") },
      forbidden: ["Authorization", "Bearer hidden"],
    },
  ];
  for (const fixture of cases) {
    const fake = createFakeHttpsRequest(fixture.fake);
    await assert.rejects(
      fetchPublicRuleDocument(baseRequest, {
        ...baseDependencies,
        httpsRequest: fake.request,
      }),
      safeError(fixture.code, fixture.forbidden),
      fixture.code,
    );
  }

  const neverCalled = () => assert.fail("request must not start");
  for (const [request, code] of [
    [{ ...baseRequest, method: "POST" }, "content_rejected"],
    [{ ...baseRequest, allowedOrigin: "https://other.example.test" }, "content_rejected"],
    [{ ...baseRequest, documentCount: PROGRAM_RULE_NETWORK_LIMITS.maxDocuments }, "budget_exceeded"],
    [{ ...baseRequest, aggregateBytes: PROGRAM_RULE_NETWORK_LIMITS.maxAggregateBytes }, "budget_exceeded"],
  ]) {
    await assert.rejects(
      fetchPublicRuleDocument(request, { ...baseDependencies, httpsRequest: neverCalled }),
      safeError(code),
    );
  }

  const aggregateOverflow = createFakeHttpsRequest({ body: ["xx"] });
  await assert.rejects(
    fetchPublicRuleDocument({
      ...baseRequest,
      aggregateBytes: PROGRAM_RULE_NETWORK_LIMITS.maxAggregateBytes - 1,
    }, {
      ...baseDependencies,
      httpsRequest: aggregateOverflow.request,
    }),
    safeError("budget_exceeded"),
  );

  const hung = createFakeHttpsRequest({ neverRespond: true });
  await assert.rejects(
    fetchPublicRuleDocument(baseRequest, {
      ...baseDependencies,
      httpsRequest: hung.request,
      timeoutMs: 5,
    }),
    safeError("budget_exceeded"),
  );
});

test("CONNECT proxy binds loopback, pins every tunnel, and closes tracked sockets", async (t) => {
  const echoServer = net.createServer((socket) => socket.pipe(socket));
  await listen(echoServer, "127.0.0.1");
  t.after(() => closeServer(echoServer));
  const echoPort = echoServer.address().port;
  let lookups = 0;
  const proxy = await createPinnedConnectProxy({
    allowedOrigin: `https://fixture.example.test:${echoPort}`,
    dependencies: {
      classifyAddress: (address) => address === "127.0.0.1",
      lookup: async () => {
        lookups += 1;
        return [{ address: "127.0.0.1", family: 4 }];
      },
    },
  });
  t.after(() => proxy.close());
  assert.equal(proxy.host, "127.0.0.1");
  assert.equal(proxy.proxyUrl, `http://127.0.0.1:${proxy.port}`);

  for (const value of ["first", "second"]) {
    const socket = await openTunnel(proxy.port, `fixture.example.test:${echoPort}`);
    socket.write(value);
    assert.equal((await once(socket, "data"))[0].toString(), value);
    socket.destroy();
  }
  assert.equal(lookups, 2);

  const live = await openTunnel(proxy.port, `fixture.example.test:${echoPort}`);
  const closed = once(live, "close");
  await proxy.close();
  await closed;
  await assert.rejects(connectClient(proxy.port), /connect/u);
});

test("CONNECT proxy rejects malformed, cross-origin, nested, and early-data requests", async (t) => {
  const echoServer = net.createServer((socket) => socket.pipe(socket));
  await listen(echoServer, "127.0.0.1");
  t.after(() => closeServer(echoServer));
  const echoPort = echoServer.address().port;
  const proxy = await createPinnedConnectProxy({
    allowedOrigin: `https://fixture.example.test:${echoPort}`,
    dependencies: {
      classifyAddress: () => true,
      lookup: async () => [{ address: "127.0.0.1", family: 4 }],
    },
    limits: {
      maxHeaderBytes: 256,
      maxRequests: 9,
      maxTunnelBytes: 64,
    },
  });
  t.after(() => proxy.close());

  const authority = `fixture.example.test:${echoPort}`;
  for (const payload of [
    `GET https://${authority}/ HTTP/1.1\r\nHost: ${authority}\r\n\r\n`,
    `CONNECT other.example.test:${echoPort} HTTP/1.1\r\nHost: other.example.test:${echoPort}\r\n\r\n`,
    `CONNECT fixture.example.test:443 HTTP/1.1\r\nHost: fixture.example.test:443\r\n\r\n`,
    `CONNECT ${authority} HTTP/1.1\r\n\r\n`,
    `CONNECT ${authority} HTTP/1.1\r\nHost: other.example.test:${echoPort}\r\n\r\n`,
    `CONNECT ${authority} HTTP/1.1\r\nProxy-Authorization: Basic hidden\r\n\r\n`,
    `CONNECT ${authority} HTTP/1.1\r\nContent-Length: 1\r\n\r\nx`,
    `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\nearly-tls-data`,
    `CONNECT ${authority} HTTP/1.1\r\nX-Large: ${"x".repeat(300)}\r\n\r\n`,
    `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`,
  ]) {
    const response = await sendRawProxyRequest(proxy.port, payload);
    assert.doesNotMatch(response, /^HTTP\/1\.1 200/u, payload.slice(0, 60));
    assert.doesNotMatch(response, /hidden|other\.example/u);
  }
});

test("CONNECT proxy rejects DNS/peer rebinding and enforces the tunnel byte cap", async (t) => {
  let upstreamBytes = 0;
  const echoServer = net.createServer((socket) => {
    socket.on("data", (chunk) => {
      upstreamBytes += chunk.length;
      socket.write(chunk);
    });
  });
  await listen(echoServer, "127.0.0.1");
  t.after(() => closeServer(echoServer));
  const echoPort = echoServer.address().port;
  const rebindingProxy = await createPinnedConnectProxy({
    allowedOrigin: `https://fixture.example.test:${echoPort}`,
    dependencies: {
      classifyAddress: () => true,
      connect: (options) => net.connect({ ...options, host: "127.0.0.1" }),
      lookup: async () => [{ address: "127.0.0.2", family: 4 }],
    },
  });
  t.after(() => rebindingProxy.close());
  const rebound = await sendRawProxyRequest(
    rebindingProxy.port,
    `CONNECT fixture.example.test:${echoPort} HTTP/1.1\r\nHost: fixture.example.test:${echoPort}\r\n\r\n`,
  );
  assert.doesNotMatch(rebound, /^HTTP\/1\.1 200/u);

  const splitEarlyDataProxy = await createPinnedConnectProxy({
    allowedOrigin: `https://fixture.example.test:${echoPort}`,
    dependencies: {
      classifyAddress: () => true,
      lookup: async () => {
        await new Promise((resolve) => setTimeout(resolve, 20));
        return [{ address: "127.0.0.1", family: 4 }];
      },
    },
  });
  t.after(() => splitEarlyDataProxy.close());
  const splitSocket = await connectClient(splitEarlyDataProxy.port);
  const splitResponse = [];
  splitSocket.on("data", (chunk) => splitResponse.push(chunk));
  splitSocket.write(
    `CONNECT fixture.example.test:${echoPort} HTTP/1.1\r\nHost: fixture.example.test:${echoPort}\r\n\r\n`,
  );
  await new Promise((resolve) => setImmediate(resolve));
  splitSocket.write("early-tls-data");
  await once(splitSocket, "close");
  assert.doesNotMatch(Buffer.concat(splitResponse).toString(), /^HTTP\/1\.1 200/u);

  const boundedProxy = await createPinnedConnectProxy({
    allowedOrigin: `https://fixture.example.test:${echoPort}`,
    dependencies: {
      classifyAddress: () => true,
      lookup: async () => [{ address: "127.0.0.1", family: 4 }],
    },
    limits: { maxTunnelBytes: 8 },
  });
  t.after(() => boundedProxy.close());
  const tunnel = await openTunnel(
    boundedProxy.port,
    `fixture.example.test:${echoPort}`,
  );
  const closed = once(tunnel, "close");
  tunnel.write("more-than-eight-bytes");
  await closed;
  assert.equal(upstreamBytes, 0);
});

test("CONNECT proxy applies a total header deadline and permits only narrower limits", async (t) => {
  await assert.rejects(
    createPinnedConnectProxy({
      allowedOrigin: "https://fixture.example.test",
      limits: { maxRequests: PROGRAM_RULE_NETWORK_LIMITS.maxRequests + 1 },
    }),
    safeError("content_rejected"),
  );

  const proxy = await createPinnedConnectProxy({
    allowedOrigin: "https://fixture.example.test",
    dependencies: {
      classifyAddress: () => true,
      lookup: async () => [{ address: "127.0.0.1", family: 4 }],
    },
    limits: { connectTimeoutMs: 20 },
  });
  t.after(() => proxy.close());
  const socket = await connectClient(proxy.port);
  const closed = once(socket, "close");
  socket.write("C");
  await closed;
});

function safeError(code, forbidden = []) {
  return (error) => {
    assert.equal(error?.code, code);
    assert.equal(error?.message, code);
    const serialized = `${error?.message ?? ""} ${JSON.stringify(error)}`;
    for (const value of forbidden ?? []) {
      assert.doesNotMatch(serialized, new RegExp(escapeRegex(value), "u"));
    }
    return true;
  };
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function createFakeHttpsRequest({
  body = ["ok"],
  headers = { "content-type": "text/plain" },
  networkError = null,
  neverRespond = false,
  remoteAddress = PUBLIC_IPV4,
  statusCode = 200,
} = {}) {
  const calls = [];
  return {
    calls,
    request(options, onResponse) {
      calls.push(options);
      const request = new EventEmitter();
      let destroyed = false;
      request.destroy = (error) => {
        if (destroyed) return;
        destroyed = true;
        if (error) setImmediate(() => request.emit("error", error));
      };
      request.end = () => {
        if (neverRespond) return;
        setImmediate(() => {
          if (networkError) {
            request.emit("error", networkError);
            return;
          }
          const socket = new EventEmitter();
          socket.connecting = true;
          socket.remoteAddress = remoteAddress;
          request.emit("socket", socket);
          socket.connecting = false;
          socket.emit("connect");
          if (destroyed) return;
          const response = new PassThrough();
          response.headers = headers;
          response.statusCode = statusCode;
          onResponse(response);
          for (const chunk of body) response.write(chunk);
          response.end();
        });
      };
      return request;
    },
  };
}

function callPinnedLookup(lookup, hostname) {
  return new Promise((resolve, reject) => {
    lookup(hostname, {}, (error, address, family) => {
      if (error) reject(error);
      else resolve({ address, family });
    });
  });
}

async function listen(server, host) {
  server.listen(0, host);
  await once(server, "listening");
}

async function closeServer(server) {
  if (!server.listening) return;
  server.close();
  await once(server, "close");
}

function connectClient(port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

async function openTunnel(port, authority) {
  const socket = await connectClient(port);
  socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
  const response = await readUntilHeader(socket);
  assert.match(response, /^HTTP\/1\.1 200 Connection Established\r\n\r\n$/u);
  return socket;
}

async function sendRawProxyRequest(port, payload) {
  const socket = await connectClient(port);
  const chunks = [];
  socket.on("data", (chunk) => chunks.push(chunk));
  socket.write(payload);
  await Promise.race([
    once(socket, "close"),
    new Promise((resolve) => setTimeout(resolve, 100)),
  ]);
  socket.destroy();
  return Buffer.concat(chunks).toString("utf8");
}

function readUntilHeader(socket) {
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const onData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      const end = buffered.indexOf("\r\n\r\n");
      if (end === -1) return;
      socket.off("data", onData);
      resolve(buffered.subarray(0, end + 4).toString("utf8"));
    };
    socket.on("data", onData);
    socket.once("error", reject);
    socket.once("close", () => {
      if (!buffered.includes("\r\n\r\n")) reject(new Error("proxy closed"));
    });
  });
}
