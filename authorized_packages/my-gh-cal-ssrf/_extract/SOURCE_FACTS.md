# Source facts — my-gh-cal-ssrf

- Upstream: calcom/cal.com **v6.2.0**
- Primary control: `validateUrlForSSRF` / `validateUrlForSSRFSync` in ssrfProtection.ts
- Primary sink: `fetch(subscriberUrl)` in sendPayload `_sendPayload`
- SaaS: HTTPS-only + private IP + blocked hostnames + metadata
- Self-hosted: allows private HTTP for internal webhooks; metadata still blocked
- Package models validation-before-fetch for expected **refute**
