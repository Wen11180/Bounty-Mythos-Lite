const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
const maxResponseBytes = 64 * 1024;

function createRemoteLeaseApiClient({
  fetchImpl = globalThis.fetch,
  getBaseUrl,
  timeoutMs = 5_000,
}) {
  if (
    typeof fetchImpl !== "function"
    || typeof getBaseUrl !== "function"
    || !Number.isInteger(timeoutMs)
    || timeoutMs < 1
  ) {
    throw new Error("remote_lease_api_client_config_required");
  }

  async function post(leaseDigest, operation, payload) {
    const origin = exactLoopbackApiOrigin(getBaseUrl());
    const digest = remoteLeaseDigest(leaseDigest);
    let response;
    try {
      response = await fetchImpl(
        `${origin}/mythos/studio/black-box-remote/leases/${digest}/${operation}`,
        {
          body: JSON.stringify(payload),
          headers: { "content-type": "application/json" },
          method: "POST",
          redirect: "error",
          signal: AbortSignal.timeout(timeoutMs),
        },
      );
    } catch {
      throw new Error("remote_lease_api_request_failed");
    }
    if (!response?.ok) {
      throw new Error("remote_lease_api_request_failed");
    }
    const body = await response.text();
    if (Buffer.byteLength(body, "utf8") > maxResponseBytes) {
      throw new Error("remote_lease_api_response_too_large");
    }
    try {
      return JSON.parse(body);
    } catch {
      throw new Error("remote_lease_api_response_invalid");
    }
  }

  return {
    authorize({ lease_digest: leaseDigest, request }) {
      if (!request || typeof request !== "object" || Array.isArray(request)) {
        return Promise.reject(new Error("remote_authorization_request_required"));
      }
      return post(leaseDigest, "authorize", request);
    },
    complete({ lease_digest: leaseDigest, outcome, request_grant_id: requestGrantId }) {
      if (!/^remote_grant_[0-9a-f]{32}$/u.test(requestGrantId ?? "")) {
        return Promise.reject(new Error("remote_request_grant_required"));
      }
      return post(leaseDigest, "complete", {
        outcome,
        request_grant_id: requestGrantId,
      });
    },
    stop({ lease_digest: leaseDigest, reason }) {
      if (typeof reason !== "string" || !/^[a-z][a-z0-9_]{0,99}$/u.test(reason)) {
        return Promise.reject(new Error("remote_stop_reason_required"));
      }
      return post(leaseDigest, "stop", { reason });
    },
  };
}

function exactLoopbackApiOrigin(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("exact_loopback_api_origin_required");
  }
  if (
    typeof value !== "string"
    || parsed.protocol !== "http:"
    || !loopbackHosts.has(parsed.hostname)
    || parsed.username
    || parsed.password
    || value !== parsed.origin
  ) {
    throw new Error("exact_loopback_api_origin_required");
  }
  return parsed.origin;
}

function remoteLeaseDigest(value) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    throw new Error("remote_lease_digest_required");
  }
  return value;
}

module.exports = { createRemoteLeaseApiClient };
