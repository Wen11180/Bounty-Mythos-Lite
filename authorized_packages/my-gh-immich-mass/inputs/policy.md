Authorized GitHub-sourced package my-gh-immich-user-mass-lab.

Source: public immich-app/immich repository on GitHub plus optional researcher-owned self-hosted Immich.
Security contact for real vulnerabilities: follow project SECURITY.md / GitHub private vulnerability reporting. Do not publicly disclose before investigation.
Review-only evidence in this package; live validation and report submission are blocked by default.
Do not store real Authorization headers, tokens, cookies, or private user data in package inputs.
Static modeling of self-update mass-assignment defense only (UserUpdateMeDto field allowlist excludes isAdmin / privilege fields before update_user).
Out of scope: automated scanners on production infrastructure without sandbox, DoS, social engineering.
