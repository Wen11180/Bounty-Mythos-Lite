# Local Candidate Hunter Safety Design

## Status

Implementation decision for the active A+B Candidate Hunter objective. This
document narrows the deployment model; it does not add any validation or report
submission capability.

## Threat Model

Mythos Studio is a single-operator desktop application. The local operating
system user is trusted. The application must reject or contain:

- LAN and remote clients.
- Browser pages from an untrusted origin.
- Artifact paths that escape the configured workspace root, including symlinks.
- Artifact content that contains secrets or attempts to manufacture scope.
- Caller-supplied scope, validation, or artifact ownership claims.

This design does not claim to defend against arbitrary code running as the same
operating-system user. LAN, hosted, and multi-tenant operation are unsupported
by this implementation.

## Decision

### Network and Desktop Boundary

Docker Compose exposes only API and Web services on `127.0.0.1`; Postgres and
Redis have no host port mapping. Container-to-container service addresses stay
unchanged. Studio derives its API and Web URLs from loopback ports and rejects
environment overrides whose URL is not the generated loopback URL. FastAPI
allows browser requests only from the generated Studio Web origin. Electron
uses a sandboxed renderer and allows navigation only within that configured
origin.

This intentionally removes support for using a Studio launcher to point at a
remote API or Web host.

### Workspace Boundary

Studio receives one configured workspace root at launch. A workspace and every
referenced artifact must resolve under that root. An artifact kind is a member
of the existing `WORKSPACE_DIRS` allowlist, and its resolved path must live
under `workspace/<kind>/` (with directories allowed for `code`). Manifest data
is untrusted input, so every read, export, benchmark, and research operation
revalidates it. A `..` path, absolute external path, or symlink escape returns
the same authorization error before reading the target.

The API no longer imports arbitrary local paths. Operators stage authorized,
pre-redacted material in the appropriate workspace directory. The HTTP source
audit route is subject to the same controlled-root policy. The CLI remains an
explicit local operator entrypoint and does not become a network service.

### Scope Guard

`parse_policy_text` produces the only rule that can authorize a campaign or
validation decision. Parsed policy defaults to `needs_review`, no allowed
validation modes, and human approval required. A validation mode is allowed
only when the policy explicitly permits that mode, the asset is explicitly in
scope, automation permits it, and an active human approval matches the plan.
`none` and `needs_review` automation always deny validation.

Campaign creation ignores caller-provided `scope_status` for authorization. It
stores a redacted serialized parsed rule in the campaign payload and derives
the campaign status from it. `allowed_tools` continues to represent read-only
research tooling; it is never a validation allowlist. Studio launch derives
the same rule from its staged policy and scope artifacts and fails before a
campaign record is created if the result is not explicitly in scope.

### Persistent Data and Migration

All JSON persistence flows through a structured redactor. A dictionary entry
whose key or sibling `name`/`key` identifies authorization, cookie, credential,
password, token, secret, or API-key data has its corresponding `value`,
`contents`, or credential payload redacted. This covers HAR headers, cookies,
query parameters, and Postman-style key/value pairs without persisting the raw
secret.

Artifacts are de-duplicated only inside the same program ownership scope. The
database replaces the global `source_hash` uniqueness constraint with a
program-scoped uniqueness constraint, and repository lookup includes the
program ID (including the explicit NULL branch). Existing SQLite databases
migrate through Alembic before Studio or persistent CLI execution. In-memory
test databases may retain metadata initialization because Alembic cannot share
their transient connection safely.

### Candidate Quality Baseline

The benchmark uses a static, secret-free fixture pack containing policy, scope,
OpenAPI, HAR, and a local FastAPI code sample. Fixed expectations are committed
independently of the current candidate output. The test drives the actual
Studio API flow and requires an authorization candidate for
`GET /files/{file_id}/export` with policy, scope, API, HAR, and code evidence.
It also requires every execution, validation, and report-submission flag to be
false.

## Rejected Alternatives

- Arbitrary HTTP file paths plus string-prefix checks: cannot reliably contain
  absolute paths, traversal, or symlinks.
- External Studio/API URL overrides: contradict the local-only threat model.
- Default validation modes inferred from generic policy text: grants authority
  that the program has not expressed.
- Expectations generated from the same run being evaluated: checks only
  self-consistency, not discovery quality.

## Verification Matrix

1. Loopback-only Compose and Studio URL tests prove no LAN or remote listener
   is configured.
2. Workspace unit and API tests prove external paths, traversal, tampered
   manifests, and symlinks are rejected before file access.
3. Policy and Scope Guard tests prove default, `none`, and ambiguous policy
   cannot allow validation.
4. Persistence tests prove structured secret values are absent from database
   payloads and the same source hash cannot cross program ownership.
5. Migration tests upgrade an old SQLite schema, preserve existing rows, and
   expose current columns and constraints.
6. The A+B fixture test proves the candidate path and its hard safety flags.

## Delivery Order

1. Boundary tests and loopback/workspace implementation.
2. Parsed-rule Scope Guard tests and fail-closed implementation.
3. Redaction, artifact ownership, and migration tests and implementation.
4. Fixed A+B end-to-end benchmark and full regression verification.
