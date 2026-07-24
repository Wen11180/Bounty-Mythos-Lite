'use strict';

/** Exact destination/DNS identity guard for a gateway-owned local-lab request. */

const net = require('node:net');

function authorizeDestination({
  scheme,
  host,
  port,
  path,
  resolvedIps = [],
  cnameChain = [],
  admission,
} = {}) {
  if (!isAdmission(admission)) return blocked('admitted_identity_required');
  if (scheme !== admission.scheme) return blocked('scheme_mismatch');
  if (normalizeHost(host) !== normalizeHost(admission.host)) return blocked('host_mismatch');
  if (Number(port) !== admission.port) return blocked('port_mismatch');
  const normalizedPath = normalizePath(path);
  if (normalizedPath === null) return blocked('unsafe_path');
  if (!pathWithinAuthority(normalizedPath, admission.path_authority)) {
    return blocked('path_not_authorized');
  }
  if (!Array.isArray(resolvedIps) || resolvedIps.length === 0) {
    return blocked('resolved_identity_required');
  }
  const actualIps = normalizeIps(resolvedIps);
  const expectedIps = normalizeIps(admission.resolved_ips);
  if (actualIps === null || expectedIps === null || actualIps.some((ip) => !isLoopback(ip))) {
    return blocked('resolved_ip_drift');
  }
  if (!equalArrays(actualIps, expectedIps)) return blocked('resolved_ip_drift');
  const actualCnames = normalizeNames(cnameChain);
  const expectedCnames = normalizeNames(admission.cname_chain);
  if (actualCnames === null || expectedCnames === null || !equalArrays(actualCnames, expectedCnames)) {
    return blocked('cname_drift');
  }
  return { allowed: true, reason: 'authorized' };
}

function isAdmission(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && ['http', 'https'].includes(value.scheme)
    && normalizeHost(value.host) !== null
    && Number.isSafeInteger(value.port)
    && value.port >= 1
    && value.port <= 65535
    && normalizePath(value.path_authority) !== null
    && Array.isArray(value.resolved_ips)
    && value.resolved_ips.length > 0
    && Array.isArray(value.cname_chain);
}

function normalizeHost(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase().replace(/\.$/u, '');
  if (!normalized || normalized.includes('/') || /\s/u.test(normalized)) return null;
  return normalized;
}

function normalizePath(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.includes('\\')) return null;
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }
  if (decoded.includes('?') || decoded.includes('#')) return null;
  const segments = decoded.split('/');
  if (segments.some((segment) => segment === '.' || segment === '..')) return null;
  return decoded || '/';
}

function pathWithinAuthority(path, authority) {
  const normalizedAuthority = normalizePath(authority);
  if (normalizedAuthority === null) return false;
  if (normalizedAuthority === '/') return true;
  const prefix = normalizedAuthority.endsWith('/')
    ? normalizedAuthority
    : `${normalizedAuthority}/`;
  return path === normalizedAuthority || path.startsWith(prefix);
}

function normalizeIps(values) {
  if (!Array.isArray(values)) return null;
  const normalized = [];
  for (const value of values) {
    if (typeof value !== 'string' || net.isIP(value) === 0) return null;
    normalized.push(value.toLowerCase());
  }
  return [...new Set(normalized)].sort();
}

function normalizeNames(values) {
  if (!Array.isArray(values)) return null;
  const names = values.map(normalizeHost);
  return names.some((value) => value === null) ? null : names;
}

function isLoopback(ip) {
  if (net.isIP(ip) === 4) return ip.startsWith('127.');
  return ip === '::1' || ip === '0:0:0:0:0:0:0:1';
}

function equalArrays(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function blocked(reason) {
  return { allowed: false, reason };
}

module.exports = { authorizeDestination };
