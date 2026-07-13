# Provenance

## Why this acquisition is lawful for this project
1. HackerOne program `nodejs` lists Node.js core SOURCE_CODE as an eligible asset class (bounty-eligible).
2. Node.js core source used here is publicly published open source.
3. Materials are used for local static modeling only inside Mythos-Lite.
4. No production website probing, no customer data, no automatic submission.

## What was fetched
Files under `_upstream/`:
- permission.js
- perm_permission.cc
- perm_fs_permission.cc
- fs.js
- SECURITY.md
- (also retained for reference: utils.js, rimraf.js, cjs_loader.js)

## What enters the hunter
Only `inputs/*` and `package.json`. Upstream raw C++/JS is reference material, not staged package input.

## Sanitizer
Package inputs intentionally omit external URL literals and secret-shaped text.
