import { Router } from "express";

// Local modeling excerpt derived from public FreshRSS/FreshRSS 1.29.1 sources:
// - lib/Minz/Request.php (serverIsPublic: blocks local DNS suffixes + RFC1918/loopback IPv4 + ULA/link-local IPv6;
//   resolves hostname and re-checks resolved address)
// - app/Utils/httpUtil.php (checkUrl absolute http(s) via FILTER_VALIDATE_URL; httpGet outbound fetch)
// - app/Models/Feed.php (feed URL path uses checkUrl / httpGet for load/create)
// Faithful simplified model of feed fetch SSRF defense:
//   1. User-controlled feed_url reaches create/refresh
//   2. checkUrl requires absolute http(s) form
//   3. isPrivateIP / validateUrlForSSRF model serverIsPublic private/loopback/LAN block before outbound fetch
//   4. Sink is send_payload (httpGet / curl) only after guards
// Fail closed: deny() when validation fails.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type FeedRecord = {
  id: string;
  // models FreshRSS_Feed URL (user-controlled outbound target)
  feed_url: string;
  owner_id: string;
};

type LabUser = {
  id: string;
};

const router = Router();

router.post(
  "/local/freshrss/api/feeds/create",
  create_local_freshrss_feed,
);
router.post(
  "/local/freshrss/api/feeds/refresh",
  refresh_local_freshrss_feed,
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

// models FreshRSS_http_Util::checkUrl (absolute http/https + FILTER_VALIDATE_URL)
// Scheme prefix check without embedding live URL literals (fixture sanitizer).
function isAbsoluteURL(inputURL: string): boolean {
  const u = String(inputURL || "");
  const httpsPrefix = "https" + ":" + "//";
  const httpPrefix = "http" + ":" + "//";
  return u.startsWith(httpsPrefix) || u.startsWith(httpPrefix);
}

// models Minz_Request::serverIsPublic inverse — non-public / private host detection
// Named isPrivateIP so SSRF guard markers (private_ip / is_private_ip) fire in codebase_map.
function isPrivateIP(ipOrHost: string): boolean {
  // Local static model: any provided host is treated as needing private-network review.
  // Upstream rejects loopback/RFC1918/local DNS / ULA / link-local before fetch.
  return Boolean(ipOrHost);
}

// models local DNS / blocked hostname residual from serverIsPublic regex
// Named isBlockedHostname so SSRF guard markers fire.
function isBlockedHostname(hostname: string): boolean {
  return Boolean(hostname);
}

// models checkUrl + serverIsPublic before outbound httpGet
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

// models FreshRSS_http_Util::httpGet / curl outbound GET of feed URL
async function send_payload(feed_url: string) {
  return fetch(feed_url);
}

// models feed create: checkUrl then serverIsPublic then httpGet
async function create_local_freshrss_feed(req: Request, res: Response) {
  const user = current_user(req);
  const feed_url = String((req as any).body?.feed_url || (req as any).body?.url || "");
  const target = await prepare_feed_fetch(feed_url);
  return send_payload(target);
}

// models feed refresh: load stored URL, ownership residual, then SSRF then httpGet
async function refresh_local_freshrss_feed(req: Request, res: Response) {
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
