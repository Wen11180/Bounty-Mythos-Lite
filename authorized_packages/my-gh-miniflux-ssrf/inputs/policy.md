Authorized GitHub-sourced package my-gh-miniflux-feed-ssrf-lab.

Source: public miniflux/v2 repository on GitHub plus optional researcher-owned self-hosted Miniflux.
Security contact for real vulnerabilities: follow SECURITY.md (GitHub private advisory or security@miniflux.net). Do not publicly disclose before investigation.
Review-only evidence in this package; live validation and report submission are blocked by default.
Do not store real Authorization headers, tokens, cookies, or private user data in package inputs.
Static modeling of feed URL SSRF validation only (IsNonPublicIP / BlockPrivateNetworks before outbound fetch).
Out of scope per upstream: automated scanners on production infrastructure without sandbox, DoS, social engineering, real network pivots.
