# Provenance

## Why this acquisition is lawful for this project
1. HackerOne program `gitlab` encourages local GDK / self-managed GitLab research and lists public product SOURCE_CODE assets.
2. GitLab CE-style source used here is publicly published open source for self-managed software.
3. Materials are used for local static modeling only inside Mythos-Lite.
4. No gitlab.com production probing, no customer data, no automatic submission.

## What was fetched
Files under `_upstream/`:
- projects.rb
- project_export.rb
- project_policy.rb
- helpers.rb
- repositories.rb
- project_snippets.rb

## What enters the hunter
Only `inputs/*` and `package.json`. Upstream raw Ruby is reference material, not staged package input.

## Sanitizer
Package inputs intentionally omit external URL literals and secret-shaped text.
