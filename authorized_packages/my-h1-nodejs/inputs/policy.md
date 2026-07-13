Authorized local research package for HackerOne program: nodejs.

## Authorization basis
- HackerOne Node.js program structured scope: SOURCE_CODE asset for Node.js core.
- Public Node.js core sources used only for local static modeling of permission-model and fs gates.
- Mythos-Lite mode: local static review only.
- Policy reminder: only Node.js core is IBB-eligible; project websites are out of scope.

## Observed control points from public core sources
- Permission Model is opt-in via runtime flags; process.permission.has(scope, reference) checks grants.
- FSPermission tracks separate fs.read and fs.write allow trees; deny_all / allow_all flags and radix path lookup.
- lib/fs.js gates path-based reads with permission.isEnabled() && !permission.has('fs.read', path) then ERR_ACCESS_DENIED.
- Symlink APIs require full fs scope when the permission model is enabled.
- SECURITY.md states permission model is defense-in-depth for trusted application code, not a sandbox against intentional misuse; symlink resolution to an allowed path is intended behavior, not a core bypass.

## In scope for THIS package
- Local modeling of permission-gated fs read/export/write/delete/symlink-style paths derived from core sources.
- Review whether a researcher-controlled Node binary/version still enforces path grants before sensitive sinks when --permission is enabled.

## Out of scope / forbidden
- nodejs.org and other project websites.
- Third-party npm modules (report to package maintainers).
- Denial of service, brute force, credential stuffing, social engineering.
- Real user private data collection or storage.
- Raw secrets, session material, or authorization headers.
- Automatic exploitation or automatic report submission.

## Handling
- Upstream raw files stay outside package inputs.
- Package inputs contain only sanitizer-safe local modeling artifacts.
- Candidates are hypotheses until human review.
