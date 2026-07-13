# Provenance

## Why this acquisition is lawful for this project
1. Container/image `calciumion/new-api` runs on this machine (observed on 127.0.0.1:3001).
2. Upstream controller sources are public open source (Calcium-Ion/new-api).
3. Materials are used for local static modeling only inside Mythos-Lite.
4. No third-party multi-tenant production targeting, no real API keys in package inputs, no automatic submission.

## What was fetched
Public upstream under `_upstream/`:
- controller/token.go
- middleware/auth.go
- controller/user.go

## What enters the hunter
Only `inputs/*` and `package.json`.

## Sanitizer
No Authorization headers, no sk- keys, no cookies, no real user emails in inputs.