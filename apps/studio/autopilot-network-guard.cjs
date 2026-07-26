'use strict';

/**
 * Destination/DNS egress guard for Autopilot pod.
 */

const net = require('net');
const ipaddr = require('ipaddr.js');

function isLoopback(ip) {
  if (!ip || net.isIP(ip) === 0) return false;
  try {
    const range = ipaddr.parse(ip).range();
    return range === 'loopback';
  } catch {
    return false;
  }
}

function authorizeDestination({
  host,
  resolvedIps = [],
  admittedIps = null,
  allowedHost,
  allowedPort,
  port,
}) {
  const normalizedHost = normalizeHost(host);
  if (normalizedHost !== normalizeHost(allowedHost) || Number(port) !== Number(allowedPort)) {
    return { allowed: false, reason: 'destination_mismatch' };
  }
  const normalizedIps = normalizeIps(resolvedIps);
  if (normalizedIps.length === 0) {
    return { allowed: false, reason: 'unresolved_or_non_lab_host' };
  }
  for (const ip of normalizedIps) {
    if (!isLoopback(ip)) {
      return { allowed: false, reason: 'dns_rebind_or_non_loopback_ip' };
    }
  }
  if (admittedIps !== null) {
    const normalizedAdmitted = normalizeIps(admittedIps);
    if (
      normalizedAdmitted.length === 0
      || normalizedAdmitted.length !== normalizedIps.length
      || normalizedAdmitted.some((ip, index) => ip !== normalizedIps[index])
    ) {
      return { allowed: false, reason: 'dns_admission_mismatch' };
    }
  }
  return { allowed: true, reason: 'authorized' };
}

function normalizeHost(value) {
  return typeof value === 'string'
    ? value.trim().toLowerCase().replace(/^\[|\]$/gu, '').replace(/\.$/u, '')
    : '';
}

function normalizeIps(values) {
  if (!Array.isArray(values)) return [];
  const result = [];
  for (const value of values) {
    if (typeof value !== 'string' || net.isIP(value) === 0) return [];
    const normalized = value.toLowerCase();
    if (!result.includes(normalized)) result.push(normalized);
  }
  return result.sort();
}

module.exports = {
  authorizeDestination,
  isLoopback,
};
