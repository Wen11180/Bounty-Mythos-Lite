# Provenance

## Why this acquisition is lawful for this project
1. Container `mythos-dvwa` runs on this machine, bound to 127.0.0.1:8080.
2. DVWA is an intentionally vulnerable local teaching application.
3. Materials are used for local static modeling only inside Mythos-Lite.
4. No internet-facing target, no third-party customer data, no automatic submission.

## What was fetched
Read-only `docker exec` excerpts under `_upstream/`:
- vulnerabilities/fi/source/low.php and impossible.php
- vulnerabilities/csrf/source/low.php and impossible.php
- vulnerabilities/sqli/source/low.php

## What enters the hunter
Only `inputs/*` and `package.json`. Upstream PHP is residual reference, not staged package input.

## Sanitizer
Package inputs intentionally omit external URL literals, secret-shaped text, and real user data.