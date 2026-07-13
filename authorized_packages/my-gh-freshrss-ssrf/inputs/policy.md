Authorized GitHub-sourced package my-gh-freshrss-feed-ssrf-lab.

Source: public FreshRSS/FreshRSS repository on GitHub plus optional researcher-owned self-hosted FreshRSS.
Security contact for real vulnerabilities: follow SECURITY.md (GitHub security advisory or alexandre@alapetite.fr).
Review-only evidence in this package; live validation and report submission are blocked by default.
Do not store real Authorization headers, tokens, cookies, or private user data in package inputs.
Static modeling of feed URL SSRF validation only (checkUrl + serverIsPublic / private-network block before httpGet).
Out of scope: automated scanners on production infrastructure without sandbox, DoS, social engineering, real network pivots.
