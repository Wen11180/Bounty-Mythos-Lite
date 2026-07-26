'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { authorizeDestination } = require('./autopilot-network-guard.cjs');

test('permits only loopback IPs and rejects host mismatches', () => {
  const ok = authorizeDestination({
    host: '127.0.0.1',
    port: 8080,
    allowedHost: '127.0.0.1',
    allowedPort: 8080,
    resolvedIps: ['127.0.0.1'],
  });
  assert.equal(ok.allowed, true);
  const bad = authorizeDestination({
    host: '127.0.0.1',
    port: 8080,
    allowedHost: '127.0.0.1',
    allowedPort: 8080,
    resolvedIps: ['203.0.113.8'],
  });
  assert.equal(bad.allowed, false);

  for (const ip of ['10.0.0.1', '192.168.1.10', 'fd00::10']) {
    const privateDestination = authorizeDestination({
      host: '127.0.0.1',
      port: 8080,
      allowedHost: '127.0.0.1',
      allowedPort: 8080,
      resolvedIps: [ip],
    });
    assert.equal(privateDestination.allowed, false, ip);
    assert.equal(privateDestination.reason, 'dns_rebind_or_non_loopback_ip');
  }

  const ipv6Loopback = authorizeDestination({
    host: '::1',
    port: 8080,
    allowedHost: '::1',
    allowedPort: 8080,
    resolvedIps: ['::1'],
  });
  assert.equal(ipv6Loopback.allowed, true);
});
