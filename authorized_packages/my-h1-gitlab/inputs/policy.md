Authorized local research package for HackerOne program: gitlab.

## Authorization basis
- HackerOne GitLab program rules.
- Strong encouragement for local GDK or self-managed GitLab research rather than gitlab.com production.
- Additional local materials: public GitLab CE-style API source excerpts used only to model self-managed behavior for static review.
- Mythos-Lite mode: local static review only.

## Observed control points from public CE-style sources
- Project resolution goes through find_project!/user_project and can read_project ability checks.
- find_project! also enforces CI job-auth project-scope and job-auth policy hooks.
- Project export status/start/download and export_relations routes run authorize_admin_project before sensitive export actions.
- Repository archive route runs authorize_read_code! before send_git_archive.
- Export download serves an archive file only after those authorization hooks.

## In scope for THIS package
- Local modeling of project show, project export, relations export, and repository archive APIs on a researcher-owned instance.
- Review whether deployed local instance still enforces the above hooks for all auth methods (session, PAT, job auth).

## Out of scope / forbidden
- gitlab.com production and other hosted customer assets.
- Other people's instances.
- Denial of service, brute force, credential stuffing, social engineering.
- Real user private data collection or storage.
- Raw secrets, session material, or authorization headers.
- Automatic exploitation or automatic report submission.

## Handling
- Upstream raw files stay outside package inputs.
- Package inputs contain only sanitizer-safe local modeling artifacts.
- Candidates are hypotheses until human review.