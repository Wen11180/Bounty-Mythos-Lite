# Provenance

## Why this acquisition is lawful for this project
1. HackerOne program `wordpress` lists WordPress Core SOURCE_CODE as an eligible asset class.
2. WordPress Core source used here is publicly published open source.
3. Materials are used for local static modeling only inside Mythos-Lite.
4. No wordpress.com production probing, no customer data, no automatic submission.

## What was fetched
Files under `_upstream/`:
- class-wp-rest-posts-controller.php
- class-wp-rest-attachments-controller.php
- class-wp-rest-users-controller.php

## What enters the hunter
Only `inputs/*` and `package.json`. Upstream raw PHP is reference material, not staged package input.

## Sanitizer
Package inputs intentionally omit external URL literals and secret-shaped text.
