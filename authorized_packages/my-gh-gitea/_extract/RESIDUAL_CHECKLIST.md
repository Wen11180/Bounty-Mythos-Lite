# RESIDUAL_CHECKLIST — Gitea issue/authz

Use only on researcher-owned self-hosted Gitea or static public source review.

Local pin: Docker gitea/gitea:1.26.4 on 127.0.0.1:3002 (mythos-gitea), GET /api/v1/version => **1.26.4**.
Static excerpts: tmp/gitea_upstream_v1.26.4/ (tag v1.26.4).

| ID | Question | Status |
| --- | --- | --- |
| GT-R1 | Does installed version still call GetIssueWithAttrsByIndex with repository.ID? | **held** — v1.26.4 issue_api.go GetIssue: GetIssueWithAttrsByIndex(ctx, ctx.Repo.Repository.ID, index) |
| GT-R2 | Does CanReadIssuesOrPulls still gate before JSON sink? | **held** — GetIssue checks ctx.Repo.CanReadIssuesOrPulls(issue.IsPull) before JSON; deny => APIErrorNotFound |
| GT-R3 | Are there alternate issue fetch routes (web vs API vs attachments) that skip unit checks? | **mostly held + soft nuance** — see notes below |
| GT-R4 | Do public-only API tokens still fail closed on private repos? | **held (fail-closed)** — static + local non-destructive check |
| GT-R5 | Cross-repo index confusion (same numeric index, different repo) blocked by repo ID scope? | **held** — GetIssueByIndex(repoID, index) composite; comments GetCommentWithRepoID(repoID, id) |

## GT-R3 notes (alternate routes, API v1)

Parent chain for repo issue group (api.go):
tokenRequiresScopes(Issue) -> repoAssignment() + checkTokenPublicOnly() -> issue routes under mustEnableIssuesOrPulls.

| Route class | Handler evidence | Gate |
| --- | --- | --- |
| GET issues/{index} | GetIssue | repo-scoped load + CanReadIssuesOrPulls(isPull) |
| GET issues/{index}/comments | ListIssueComments | GetIssueByIndex(repoID) + CanReadIssuesOrPulls |
| GET issues/comments/{id} | GetIssueComment | GetCommentWithRepoID(repoID,id) + CanReadIssuesOrPulls |
| GET issues/search | SearchIssues | buildSearchIssuesRepoIDs + ApplyPublicOnly; indexer limited to accessible repo IDs |
| GET issues/{index}/dependencies|blocks | GetIssueDependencies / GetIssueBlocks | repo-scoped load + CanReadIssuesOrPulls; cross-repo deps re-check GetDoerRepoPermission + CanReadIssuesOrPulls |
| Reactions | GetIssueCommentReactions / issue reactions | comment/issue repo ID match + CanReadIssuesOrPulls |
| GET issues/{index}/timeline | ListIssueCommentsAndTimeline | **no handler-level CanReadIssuesOrPulls(isPull)** after load; relies on parent mustEnableIssuesOrPulls (Issues OR Pulls). Cross-ref comments filtered via isXRefCommentAccessible |
| GET issues/{index}/assets* | getIssueFromContext | **no handler-level CanReadIssuesOrPulls(isPull)**; attachmentBelongsToRepoOrIssue enforces attachment.RepoID/IssueID |
| subscriptions on issue | GetIssueSubscribers / setIssueSubscription | GetIssueByIndex(repoID); **no explicit isPull unit re-check** in handler |

Soft residual (not confirmed vuln, not a final):
If a principal can read **Issues** unit but not **PullRequests** unit, parent middleware still admits the issue group. Handlers that omit isPull unit re-check may expose PR-adjacent data (timeline/assets/subscribers) that GetIssue would 404. Repo membership/visibility still applies. Needs optional multi-unit permission matrix on owned instance before any claim.

## GT-R4 notes

Static:
- AccessTokenScopePublicOnly = public-only
- API middleware checkTokenPublicOnly: PublicOnly + !TokenCanAccessRepo => 403 (issue category message)
- Web CheckTokenScopes: PublicOnly + repo.IsPrivate => 403

Local non-destructive (researcher-owned, test accounts only, no real user data):
- full-scope token: create private+public repos/issues; private GET issue => 200
- public-only token: private issue GET => **not 200** (observed **404** empty; fail-closed, status may be 403/404 depending path)
- public-only token: public issue GET => 200

No private issue body returned under public-only token.

## Rules
- Do not attack public third-party Gitea hosts.
- Do not invent unguarded inputs that contradict SOURCE_FACTS.
- Submission remains blocked unless human policy review says otherwise.
- Do not store raw access tokens in package docs.

Updated: 2026-07-12T11:02:05Z

## Live unauth fail-closed matrix (2026-07-12)

Researcher-owned `127.0.0.1:3002`, no credentials, no secrets stored:

| Path | Status |
| --- | --- |
| GET /api/v1/version | 200 (`1.26.4`) |
| GET /api/v1/user | 401 |
| GET /api/v1/repos/search?q=mythos&limit=1 | 200 empty |
| GET /api/v1/settings/api | 200 paging-only |
| GET /api/v1/repos/nosuch/nosuch/issues/1 | 404 |
| GET /api/v1/repos/nosuch/nosuch/issues/1/timeline | 404 |
| GET /api/v1/repos/nosuch/nosuch/issues/1/assets | 404 |

Probe timeouts under burst loops are not findings. Soft multi-unit GT-R3 note unchanged (no multi-unit account matrix this pass).

Updated live matrix: 2026-07-12T16:45:00Z

## Live residual depth (2026-07-12T17:45)

Researcher-owned `127.0.0.1:3002`, unauth GET only, no secrets stored:

| Class | Observation |
| --- | --- |
| Version | 200 `1.26.4` |
| /api/v1/user, /user/repos, /notifications, /admin/* | **401** |
| Missing repo issue/timeline/assets/reactions/deps | **404** |
| Unauth repos/search | public only; private_visible=0 |
| Private-name guesses | **404** |
| Public lab repo issue/1 + comments/timeline/assets/deps/blocks/reactions/labels | **200** |
| Public lab /collaborators /hooks /keys /teams | **401** |
| GT-R3 dual-unit Issues vs Pulls matrix | **not run this pass** (soft static note retained) |
| users/search email field | may be present depending privacy config; **values not stored** |

Updated live depth: 2026-07-12T17:45:00Z
## GT-R3 dual-unit live matrix (2026-07-12)

Researcher-owned Gitea **1.26.4** @ `127.0.0.1:3002`.
Private org repo only (public visibility would collapse unit gates).
Team-scoped principals (org teams; session lab accounts; **no tokens/passwords stored**):

| Principal | Team units |
| --- | --- |
| unitissues | `repo.code` + `repo.issues` write (**no** `repo.pulls`) |
| unitpulls | `repo.code` + `repo.pulls` write (**no** `repo.issues`) |

Indices: pure issue `#I`, PR issue-index `#P` (owner-created). Non-destructive GET matrix.

| Surface | unitissues | unitpulls | mythosadmin | unauth |
| --- | --- | --- | --- | --- |
| GET issues/`#I` | **200** | **404** | 200 | 404 |
| GET issues/`#I`/comments | **200** | **404** | 200 | — |
| GET issues/`#I`/timeline | 200 | **200** | 200 | — |
| GET issues/`#I`/assets | 200 | **200** | 200 | — |
| GET issues/`#I`/subscriptions | 200 | **200** | 200 | — |
| GET issues/`#P` (PR as issue) | **404** | **200** | 200 | — |
| GET issues/`#P`/comments | **404** | 200 | 200 | — |
| GET issues/`#P`/timeline | **200** | 200 | 200 | — |
| GET issues/`#P`/assets | **200** | 200 | 200 | — |
| GET issues/`#P`/subscriptions | **200** | 200 | 200 | — |
| GET pulls/`#P` | **404** | **200** | 200 | — |
| GET pulls/`#I` | 404 | 404 | 404 | — |
| list issues | **200** | **404** | 200 | — |
| list pulls | **404** | **200** | 200 | — |

### Interpretation (honest)

1. **Hard gates held** for primary object JSON:
   - Issues-only cannot `GET issues/#P` (PR) or `GET pulls/#P` or list pulls → **404**
   - Pulls-only cannot `GET issues/#I` or list issues → **404**
   - Matches static `CanReadIssuesOrPulls(isPull)` on GetIssue / list surfaces.

2. **Soft residual confirmed on private dual-unit principals** (not a confirmed vuln claim, not a final, submission blocked):
   - Issues-only still receives **200** on PR-index **timeline / assets / subscriptions** even though `GET issues/#P` is **404**.
   - Pulls-only still receives **200** on issue-index **timeline / assets / subscriptions** even though `GET issues/#I` is **404**.
   - Aligns with static note: those handlers omit handler-level `CanReadIssuesOrPulls(isPull)` and rely on parent `mustEnableIssuesOrPulls` (Issues **OR** Pulls).

3. Repo membership/visibility still required (private repo; unauth issue **404**). Not remote unauth disclosure.

4. Collaborator permission API may report role `none` for pure team members; access still enforced via team units. Do not treat collaborator endpoint alone as unit truth.

5. No secrets stored in package docs. Lab passwords were session-only resets and not written here.

GT-R3 status: **mostly_held + soft residual confirmed on dual-unit matrix** (human review only; no auto-submit).

Updated dual-unit matrix: 2026-07-12T18:30:00Z
