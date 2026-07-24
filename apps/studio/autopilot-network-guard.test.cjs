'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { authorizeDestination } = require('./autopilot-network-guard.cjs');

test('allows only the exact admitted scheme, host, port, path, CNAME, and IP identity', () => {
  const admission = admittedIdentity();
  const ok = authorizeDestination({
    scheme: 'http',
    host: 'localhost',
    port: 8080,
    path: '/api/objects/owned',
    resolvedIps: ['127.0.0.1', '::1'],
    cnameChain: ['localhost'],
    admission,
  });
  assert.deepEqual(ok, { allowed: true, reason: 'authorized' });

  const cases = [
    [{ scheme: 'https' }, 'scheme_mismatch'],
    [{ host: '127.0.0.1' }, 'host_mismatch'],
    [{ port: 8081 }, 'port_mismatch'],
    [{ path: '/other' }, 'path_not_authorized'],
    [{ resolvedIps: [] }, 'resolved_identity_required'],
    [{ resolvedIps: ['127.0.0.2'] }, 'resolved_ip_drift'],
    [{ cnameChain: ['alias.localhost'] }, 'cname_drift'],
  ];
  for (const [updates, reason] of cases) {
    const result = authorizeDestination({
      scheme: 'http',
      host: 'localhost',
      port: 8080,
      path: '/api/objects/owned',
      resolvedIps: ['127.0.0.1', '::1'],
      cnameChain: ['localhost'],
      admission,
      ...updates,
    });
    assert.deepEqual(result, { allowed: false, reason });
  }
});

test('fails closed for public, private-network, malformed, and traversal drift', () => {
  const admission = admittedIdentity();
  for (const resolvedIps of [
    ['203.0.113.8'],
    ['10.0.0.8'],
    ['not-an-ip'],
  ]) {
    assert.equal(authorizeDestination({
      scheme: 'http',
      host: 'localhost',
      port: 8080,
      path: '/api',
      resolvedIps,
      cnameChain: ['localhost'],
      admission,
    }).allowed, false);
  }
  assert.deepEqual(authorizeDestination({
    scheme: 'http',
    host: 'localhost',
    port: 8080,
    path: '/api/../admin',
    resolvedIps: ['127.0.0.1', '::1'],
    cnameChain: ['localhost'],
    admission,
  }), { allowed: false, reason: 'unsafe_path' });
});

function admittedIdentity() {
  return {
    scheme: 'http',
    host: 'localhost',
    port: 8080,
    path_authority: '/api',
    cname_chain: ['localhost'],
    resolved_ips: ['127.0.0.1', '::1'],
  };
}
