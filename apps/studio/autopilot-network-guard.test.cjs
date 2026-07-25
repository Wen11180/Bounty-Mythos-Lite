'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { authorizeDestination } = require('./autopilot-network-guard.cjs');

test('blocks public IP and host mismatch', () => {
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
});
