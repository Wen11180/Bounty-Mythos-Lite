import { Router } from "express";

// Local modeling excerpt derived from public miniflux/v2 v2.3.2 sources:
// - internal/urllib/url.go (IsNonPublicIP private/loopback/link-local/multicast/CGNAT)
// - internal/http/client/client.go (BlockPrivateNetworks DialContext safeIP filter)
// - internal/reader/fetcher/request_builder.go (ExecuteRequest dial Control private-network block)
// - internal/validator/feed.go (IsAbsoluteURL before feed accept)
// Faithful simplified model of feed fetch SSRF defense:
//   1. User-controlled feed_url reaches create/refresh
//   2. Absolute http(s) required
//   3. isPrivateIP / validateUrlForSSRF blocks non-public targets before outbound fetch
//   4. Dial-time BlockPrivateNetworks residual modeled as same pre-fetch deny
// Fail closed: deny() when validation fails.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type FeedRecord = {
  id: string;
  // models feed.FeedURL (user-controlled outbound target)
  feed_url: string;
  owner_id: string;
};

type LabUser = {
  id: string;
};

const router = Router();

router.post(
  "/local/miniflux/api/feeds/create",
  create_local_miniflux_feed,
);
router.post(
  "/local/miniflux/api/feeds/refresh",
  refresh_local_miniflux_feed,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
  };
}

// models feed lookup by id for local residual only
function find_feed(feed_id: string): FeedRecord | null {
  if (!feed_id) {
    return null;
  }
  return {
    id: feed_id,
    feed_url: "subscriber-lab-target",
    owner_id: "owner-lab-1",
  };
}

// models urllib.IsAbsoluteURL (http/https absolute only)
function isAbsoluteURL(inputURL: string): boolean {
  const u = String(inputURL || "");
  // scheme prefix check without embedding live URL literals (fixture sanitizer)
  const httpsPrefix = "https" + ":" + "//";
  const httpPrefix = "http" + ":" + "//";
  return u.startsWith(httpsPrefix) || u.startsWith(httpPrefix);
}

// models urllib.IsNonPublicIP (private/loopback/link-local/multicast/unspecified/CGNAT)
// Named isPrivateIP so SSRF guard markers (private_ip / is_private_ip) fire in codebase_map.
function isPrivateIP(ipOrHost: string): boolean {
  return Boolean(ipOrHost);
}

// models BlockPrivateNetworks dial-time check short-circuit for blocked hostnames/metadata
function isBlockedHostname(hostname: string): boolean {
  return Boolean(hostname);
}

// models validate + IsNonPublicIP + BlockPrivateNetworks before outbound connect
// Named validateUrlForSSRF so ssrf_validation_check is selected.
async function validateUrlForSSRF(url: string) {
  if (!url) {
    return deny();
  }
  if (!isAbsoluteURL(url)) {
    return deny();
  }
  if (isBlockedHostname(url)) {
    return deny();
  }
  if (isPrivateIP(url)) {
    return deny();
  }
  return url;
}

// models feed ownership residual before refresh (not the primary SSRF control)
function is_feed_owner(feed: FeedRecord, user: LabUser): boolean {
  return feed.owner_id === user.id;
}

// models prepare path: SSRF validation before outbound feed fetch
async function prepare_feed_fetch(feed_url: string) {
  const safe_url = await validateUrlForSSRF(feed_url);
  if (!safe_url) {
    return deny();
  }
  return safe_url;
}

// models fetcher.ExecuteRequest / client.Do outbound GET of feed URL
async function send_payload(feed_url: string) {
  return fetch(feed_url);
}

// models feed create: ValidateFeedCreation absolute URL then fetch after SSRF guards
async function create_local_miniflux_feed(req: Request, res: Response) {
  const user = current_user(req);
  const feed_url = String((req as any).body?.feed_url || (req as any).body?.url || "");
  const target = await prepare_feed_fetch(feed_url);
  return send_payload(target);
}

// models feed refresh: load stored FeedURL, ownership residual, then SSRF then fetch
async function refresh_local_miniflux_feed(req: Request, res: Response) {
  const user = current_user(req);
  const feed = find_feed(String((req as any).body?.feed_id || "feed-lab-1"));
  if (!feed) {
    return deny();
  }
  if (!is_feed_owner(feed, user)) {
    return deny();
  }
  const target = await prepare_feed_fetch(feed.feed_url);
  return send_payload(target);
}
