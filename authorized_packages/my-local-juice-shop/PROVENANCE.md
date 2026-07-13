# Provenance

## Why this acquisition is lawful for this project
1. OWASP Juice Shop is an intentionally vulnerable open-source lab application (MIT).
2. This machine has a local `juice-shop` Docker image/container for researcher use.
3. Materials are used for local static modeling only inside Mythos-Lite.
4. No third-party production instance, no real customer data, no automatic submission.

## What was fetched
Public upstream route excerpts under `_upstream/` from juice-shop/juice-shop:
- basket.ts (primary: retrieveBasket IDOR teaching challenge)
- order.ts, fileServer.ts, userProfile.ts, security.ts (context)

## What enters the hunter
Only `inputs/*` and `package.json`. Upstream raw TS is residual reference.

## Sanitizer
Package inputs omit external URL literals, secret-shaped text, and real user data.