Authorized GitHub-sourced package my-gh-cal-webhook-ssrf-lab.

Source: public calcom/cal.com repository on GitHub plus optional researcher-owned self-hosted Cal.com.
Security contact for real vulnerabilities: follow SECURITY.md and report to security@cal.com (do not publicly disclose before investigation).
Review-only evidence in this package; live validation and report submission are blocked by default.
Do not store real Authorization headers, tokens, cookies, or private user data in package inputs.
Static modeling of webhook subscriberUrl SSRF validation only (validateUrlForSSRF before fetch).
Out of scope per upstream: automated scanners on production infrastructure without sandbox, DoS, social engineering, real network pivots.
