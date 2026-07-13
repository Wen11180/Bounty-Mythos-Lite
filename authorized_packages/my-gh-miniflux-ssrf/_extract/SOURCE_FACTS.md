# Source facts ? my-gh-miniflux-ssrf

- Upstream: miniflux/v2 **v2.3.2**
- Primary control: `urllib.IsNonPublicIP` (private/loopback/link-local/multicast/unspecified + RFC6598 CGNAT)
- Primary dial guard: `http/client.NewClientWithOptions` with `BlockPrivateNetworks` ? connect-time IP check eliminates DNS-rebinding TOCTOU
- Fetcher path: `reader/fetcher.RequestBuilder.ExecuteRequest` also dial-controls private networks unless `FetcherAllowPrivateNetworks`
- Feed create/modify: `validator.ValidateFeedCreation` requires absolute http(s) URL via `urllib.IsAbsoluteURL`
- Primary sink: outbound GET/fetch of user-controlled feed URL
- Package models validation-before-fetch for expected **refute**
