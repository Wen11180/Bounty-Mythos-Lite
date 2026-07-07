# Mythos Studio Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first local Mythos Studio prototype: a desktop-style, chat-first workspace that imports authorized materials, runs an existing safe research pass, displays candidate cards, and exports submission-blocked report drafts.

**Architecture:** Reuse the current FastAPI and Next.js surfaces instead of rewriting the product. Add a small workspace model and Studio API on the backend, a focused `/studio` operator surface on the frontend, and an Electron launcher that starts the local API and web app in a desktop window without requiring manual Docker startup.

**Tech Stack:** FastAPI, Pydantic, pytest, Next.js 16, React 19, TypeScript, Node test runner, Electron.

---

## File Map

- Create `apps/api/app/studio_workspace.py`: local workspace manifest loading, import recording, safe scope validation, candidate shaping, and export path helpers.
- Create `apps/api/tests/test_studio_workspace.py`: unit coverage for manifest creation, artifact imports, source-audit run receipts, and report export safety.
- Modify `apps/api/app/main.py`: add Studio request/response models and `/mythos/studio/*` endpoints that wrap `studio_workspace` and existing source-audit/pipeline functions.
- Create `apps/api/tests/test_studio_api.py`: API regression coverage for create workspace, import artifact, run research, list candidates, and export report.
- Create `apps/web/lib/studio-data.ts`: TypeScript view models and mappers for workspace, candidates, safety gates, conversation events, and export status.
- Create `apps/web/lib/studio-data.test.ts`: mapper tests that prove unsafe or missing candidate fields stay visibly blocked.
- Create `apps/web/app/studio/page.tsx`: the local Studio workspace view with Workspaces, Conversation, Candidate Board, and Safety/Run Log regions.
- Modify `apps/web/lib/api.ts`: add Studio API client functions and types.
- Modify `apps/web/package.json`: add Electron development and start scripts if the desktop package is kept inside `apps/web`.
- Create `apps/studio/package.json`: desktop launcher package if a separate shell is preferred.
- Create `apps/studio/main.cjs`: Electron main process that starts local API and web processes, opens the Studio window, and shuts children down cleanly.
- Create `apps/studio/README.md`: local launch instructions and safety notes.
- Modify `README.md`: point normal users at Mythos Studio as the preferred local software entrypoint.

---

## Task 1: Backend Workspace Core

**Files:**
- Create: `apps/api/app/studio_workspace.py`
- Create: `apps/api/tests/test_studio_workspace.py`

- [x] **Step 1: Write failing tests for workspace manifest behavior**

Create `apps/api/tests/test_studio_workspace.py`:

```python
from pathlib import Path

from app.studio_workspace import (
    StudioArtifactImport,
    create_workspace,
    import_workspace_artifact,
    load_workspace_manifest,
)


def test_create_workspace_writes_local_manifest(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    manifest = load_workspace_manifest(workspace.path)

    assert workspace.path == tmp_path / "acme-api"
    assert manifest["name"] == "acme-api"
    assert manifest["safety"]["scope_guard_status"] == "missing_scope"
    assert manifest["artifacts"] == []
    assert manifest["runs"] == []


def test_import_workspace_artifact_records_reference_without_copying_secret_text(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    policy_path = tmp_path / "policy.md"
    policy_path.write_text("Authorization: Bearer secret-token\nin scope api.example.com", encoding="utf-8")

    updated = import_workspace_artifact(
        workspace.path,
        StudioArtifactImport(kind="policy", source_path=str(policy_path)),
    )

    artifact = updated["artifacts"][0]
    assert artifact["kind"] == "policy"
    assert artifact["source_path"] == str(policy_path)
    assert artifact["sensitivity_label"] == "sensitive"
    assert artifact["redaction_status"] == "needs_review"
    assert "secret-token" not in str(updated)
```

- [x] **Step 2: Run tests to confirm RED**

Run:

```powershell
cd apps/api
python -m pytest tests/test_studio_workspace.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.studio_workspace'`.

- [x] **Step 3: Implement the workspace manifest module**

Create `apps/api/app/studio_workspace.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


SECRET_MARKERS = (
    "authorization:",
    "bearer ",
    "cookie:",
    "set-cookie:",
    "x-api-key",
    "api_key",
    "access_token",
    "secret",
    "token",
)


@dataclass(frozen=True)
class StudioWorkspace:
    path: Path
    manifest: dict[str, Any]


@dataclass(frozen=True)
class StudioArtifactImport:
    kind: str
    source_path: str


def create_workspace(root: str | Path, *, name: str) -> StudioWorkspace:
    workspace_path = Path(root) / _safe_name(name)
    workspace_path.mkdir(parents=True, exist_ok=True)
    for child in ("policy", "scope", "api", "har", "code", "evidence", "reports", "runs"):
        (workspace_path / child).mkdir(exist_ok=True)
    manifest = {
        "name": name,
        "created_at": _now(),
        "artifacts": [],
        "runs": [],
        "safety": {
            "scope_guard_status": "missing_scope",
            "blocked_actions": [
                "execute_live_validation",
                "touch_real_user_data",
                "submit_report",
            ],
        },
    }
    _write_manifest(workspace_path, manifest)
    return StudioWorkspace(path=workspace_path, manifest=manifest)


def load_workspace_manifest(workspace_path: str | Path) -> dict[str, Any]:
    path = Path(workspace_path) / "manifest.json"
    return json.loads(path.read_text(encoding="utf-8"))


def import_workspace_artifact(
    workspace_path: str | Path,
    artifact: StudioArtifactImport,
) -> dict[str, Any]:
    manifest = load_workspace_manifest(workspace_path)
    source = Path(artifact.source_path)
    digest = _file_digest(source)
    sensitivity = _sensitivity(source)
    record = {
        "kind": artifact.kind,
        "source_path": str(source),
        "source_hash": digest,
        "sensitivity_label": sensitivity,
        "redaction_status": "needs_review" if sensitivity == "sensitive" else "not_required",
        "imported_at": _now(),
    }
    manifest["artifacts"].append(record)
    if artifact.kind == "scope":
        manifest["safety"]["scope_guard_status"] = "scope_imported"
    _write_manifest(workspace_path, manifest)
    return manifest


def record_workspace_run(
    workspace_path: str | Path,
    *,
    run_id: str,
    status: str,
    report_path: str | None,
    candidate_count: int,
) -> dict[str, Any]:
    manifest = load_workspace_manifest(workspace_path)
    manifest["runs"].append(
        {
            "run_id": run_id,
            "status": status,
            "report_path": report_path,
            "candidate_count": candidate_count,
            "recorded_at": _now(),
        }
    )
    _write_manifest(workspace_path, manifest)
    return manifest


def _write_manifest(workspace_path: str | Path, manifest: dict[str, Any]) -> None:
    Path(workspace_path).mkdir(parents=True, exist_ok=True)
    (Path(workspace_path) / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value.strip())
    return cleaned or "workspace"


def _file_digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _sensitivity(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return "unknown"
    lowered = text.lower()
    return "sensitive" if any(marker in lowered for marker in SECRET_MARKERS) else "low"


def _now() -> str:
    return datetime.now(UTC).isoformat()
```

- [x] **Step 4: Run tests to confirm GREEN**

Run:

```powershell
cd apps/api
python -m pytest tests/test_studio_workspace.py -q
```

Expected: `2 passed`.

---

## Task 2: Studio API Endpoints

**Files:**
- Modify: `apps/api/app/main.py`
- Create: `apps/api/tests/test_studio_api.py`

- [x] **Step 1: Write failing API tests**

Create `apps/api/tests/test_studio_api.py`:

```python
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_studio_workspace_create_import_and_manifest(tmp_path: Path):
    response = client.post(
        "/mythos/studio/workspaces",
        json={"root_path": str(tmp_path), "name": "acme-api"},
    )
    assert response.status_code == 200
    workspace_path = response.json()["path"]

    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(f'allowed_repos:\n  - "{tmp_path}"\n', encoding="utf-8")
    import_response = client.post(
        "/mythos/studio/workspaces/imports",
        json={
            "workspace_path": workspace_path,
            "kind": "scope",
            "source_path": str(scope_path),
        },
    )

    assert import_response.status_code == 200
    assert import_response.json()["safety"]["scope_guard_status"] == "scope_imported"
    assert import_response.json()["artifacts"][0]["kind"] == "scope"


def test_studio_workspace_rejects_missing_artifact_path(tmp_path: Path):
    response = client.post(
        "/mythos/studio/workspaces",
        json={"root_path": str(tmp_path), "name": "acme-api"},
    )
    workspace_path = response.json()["path"]

    import_response = client.post(
        "/mythos/studio/workspaces/imports",
        json={
            "workspace_path": workspace_path,
            "kind": "policy",
            "source_path": str(tmp_path / "missing.md"),
        },
    )

    assert import_response.status_code == 404
    assert import_response.json()["detail"] == "artifact_source_not_found"
```

- [ ] **Step 2: Run tests to confirm RED** *(not rerun in this checkpoint because the implementation was already present)*

Run:

```powershell
cd apps/api
python -m pytest tests/test_studio_api.py -q
```

Expected: FAIL with `404 Not Found` for `/mythos/studio/workspaces`.

- [x] **Step 3: Add request models and endpoints**

Modify `apps/api/app/main.py`.

Add imports near existing imports:

```python
from app.studio_workspace import (
    StudioArtifactImport,
    create_workspace,
    import_workspace_artifact,
    load_workspace_manifest,
)
```

Add request models near other request models:

```python
class StudioWorkspaceCreateRequest(BaseModel):
    root_path: str = Field(min_length=1)
    name: str = Field(min_length=1, max_length=255)


class StudioArtifactImportRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    kind: str = Field(min_length=1, max_length=50)
    source_path: str = Field(min_length=1)
```

Add endpoints near the source-audit endpoints:

```python
@app.post("/mythos/studio/workspaces")
def create_mythos_studio_workspace(request: StudioWorkspaceCreateRequest) -> dict:
    workspace = create_workspace(request.root_path, name=request.name)
    return {
        "path": str(workspace.path),
        "manifest": workspace.manifest,
    }


@app.get("/mythos/studio/workspaces/manifest")
def get_mythos_studio_workspace_manifest(workspace_path: str) -> dict:
    path = Path(workspace_path)
    if not (path / "manifest.json").exists():
        raise HTTPException(status_code=404, detail="workspace_manifest_not_found")
    return load_workspace_manifest(path)


@app.post("/mythos/studio/workspaces/imports")
def import_mythos_studio_workspace_artifact(request: StudioArtifactImportRequest) -> dict:
    source = Path(request.source_path)
    if not source.exists():
        raise HTTPException(status_code=404, detail="artifact_source_not_found")
    return import_workspace_artifact(
        request.workspace_path,
        StudioArtifactImport(kind=request.kind, source_path=request.source_path),
    )
```

- [x] **Step 4: Run API tests**

Run:

```powershell
cd apps/api
python -m pytest tests/test_studio_workspace.py tests/test_studio_api.py -q
```

Expected: all tests pass.

---

## Task 3: Studio Candidate View Model

**Files:**
- Create: `apps/web/lib/studio-data.ts`
- Create: `apps/web/lib/studio-data.test.ts`

- [x] **Step 1: Write failing mapper tests**

Create `apps/web/lib/studio-data.test.ts`:

```typescript
import assert from "node:assert/strict";
import test from "node:test";

import { toStudioCandidateCards, toStudioWorkspaceSummary } from "./studio-data";

test("toStudioWorkspaceSummary keeps missing scope visibly blocked", () => {
  const summary = toStudioWorkspaceSummary({
    name: "acme-api",
    artifacts: [],
    runs: [],
    safety: {
      scope_guard_status: "missing_scope",
      blocked_actions: ["execute_live_validation"],
    },
  });

  assert.equal(summary.name, "acme-api");
  assert.equal(summary.scopeGuardLabel, "Missing scope");
  assert.deepEqual(summary.blockedActions, ["execute_live_validation"]);
});

test("toStudioCandidateCards maps missing endpoint and code path as review gaps", () => {
  const cards = toStudioCandidateCards([
    {
      hypothesis_id: "H-001",
      vuln_type: "IDOR",
      risk: "high",
      location: "",
      reason: "Handler reads an object by id.",
      evidence_needed: ["two test accounts"],
      false_positive_checks: ["ownership may be enforced in middleware"],
      safe_verification: true,
      priority_score: 80,
    },
  ]);

  assert.equal(cards[0].id, "H-001");
  assert.equal(cards[0].affectedEndpoint, "Endpoint needs review");
  assert.equal(cards[0].affectedCodePath, "Code path needs review");
  assert.equal(cards[0].status, "needs_review");
});
```

- [ ] **Step 2: Run tests to confirm RED** *(not rerun in this checkpoint because the implementation was already present)*

Run:

```powershell
cd apps/web
npm test -- lib/studio-data.test.ts
```

Expected: FAIL with module not found for `./studio-data`.

- [x] **Step 3: Implement Studio mappers**

Create `apps/web/lib/studio-data.ts`:

```typescript
export type StudioWorkspaceManifest = {
  name?: string;
  artifacts?: Array<{ kind?: string; source_path?: string; redaction_status?: string }>;
  runs?: Array<{ run_id?: string; status?: string; candidate_count?: number }>;
  safety?: {
    scope_guard_status?: string;
    blocked_actions?: string[];
  };
};

export type StudioWorkspaceSummary = {
  name: string;
  artifactCount: number;
  runCount: number;
  scopeGuardLabel: string;
  blockedActions: string[];
};

export type StudioCandidateInput = {
  hypothesis_id?: string;
  vuln_type?: string;
  risk?: string;
  location?: string;
  reason?: string;
  evidence_needed?: string[];
  false_positive_checks?: string[];
  safe_verification?: boolean;
  priority_score?: number;
  source_facts?: Array<{ route_path?: string; source_path?: string; symbol_name?: string }>;
};

export type StudioCandidateCard = {
  id: string;
  title: string;
  severity: string;
  status: "needs_review" | "blocked" | "needs_evidence";
  affectedEndpoint: string;
  affectedCodePath: string;
  evidenceNeeds: string[];
  refutationQuestions: string[];
  priorityScore: number;
};

export function toStudioWorkspaceSummary(
  manifest: StudioWorkspaceManifest,
): StudioWorkspaceSummary {
  return {
    name: safeText(manifest.name, "Untitled workspace"),
    artifactCount: manifest.artifacts?.length ?? 0,
    runCount: manifest.runs?.length ?? 0,
    scopeGuardLabel: scopeGuardLabel(manifest.safety?.scope_guard_status),
    blockedActions: manifest.safety?.blocked_actions ?? [],
  };
}

export function toStudioCandidateCards(
  candidates: StudioCandidateInput[],
): StudioCandidateCard[] {
  return candidates.slice(0, 5).map((candidate, index) => {
    const endpoint = endpointFromCandidate(candidate);
    const codePath = codePathFromCandidate(candidate);
    const blocked = candidate.safe_verification === false;
    return {
      id: safeText(candidate.hypothesis_id, `H-${String(index + 1).padStart(3, "0")}`),
      title: safeText(candidate.vuln_type, "Candidate hypothesis"),
      severity: safeText(candidate.risk, "medium"),
      status: blocked ? "blocked" : endpoint && codePath ? "needs_evidence" : "needs_review",
      affectedEndpoint: endpoint || "Endpoint needs review",
      affectedCodePath: codePath || "Code path needs review",
      evidenceNeeds: candidate.evidence_needed ?? [],
      refutationQuestions: candidate.false_positive_checks ?? [],
      priorityScore: candidate.priority_score ?? 0,
    };
  });
}

function endpointFromCandidate(candidate: StudioCandidateInput): string {
  const route = candidate.source_facts?.find((fact) => fact.route_path)?.route_path;
  return route || safeText(candidate.location, "");
}

function codePathFromCandidate(candidate: StudioCandidateInput): string {
  const fact = candidate.source_facts?.find((item) => item.source_path || item.symbol_name);
  if (!fact) {
    return "";
  }
  return [fact.source_path, fact.symbol_name].filter(Boolean).join(":");
}

function scopeGuardLabel(value: string | undefined): string {
  if (value === "scope_imported") {
    return "Scope imported";
  }
  if (value === "allowed") {
    return "Allowed";
  }
  if (value === "blocked") {
    return "Blocked";
  }
  return "Missing scope";
}

function safeText(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}
```

- [x] **Step 4: Run mapper tests**

Run:

```powershell
cd apps/web
npm test -- lib/studio-data.test.ts
```

Expected: tests pass.

---

## Task 4: Studio UI Surface

**Files:**
- Create: `apps/web/app/studio/page.tsx`
- Modify: `apps/web/lib/api.ts`
- Test: `apps/web/lib/studio-data.test.ts`

- [x] **Step 1: Add a static structure test for the Studio page**

Append to `apps/web/lib/studio-data.test.ts`:

```typescript
import fs from "node:fs/promises";

test("studio page exposes the four studio regions", async () => {
  const page = await fs.readFile(new URL("../app/studio/page.tsx", import.meta.url), "utf8");

  assert.match(page, /Workspaces/);
  assert.match(page, /Conversation/);
  assert.match(page, /Candidate Board/);
  assert.match(page, /Safety and Run Log/);
  assert.match(page, /submission-blocked/);
});
```

- [ ] **Step 2: Run test to confirm RED** *(not rerun in this checkpoint because the page was already present when verified)*

Run:

```powershell
cd apps/web
npm test -- lib/studio-data.test.ts
```

Expected: FAIL because `apps/web/app/studio/page.tsx` does not exist.

- [x] **Step 3: Add the first Studio page**

Create `apps/web/app/studio/page.tsx`:

```tsx
import Link from "next/link";

import { toStudioCandidateCards, toStudioWorkspaceSummary } from "@/lib/studio-data";

const workspace = toStudioWorkspaceSummary({
  name: "Local Mythos Studio",
  artifacts: [],
  runs: [],
  safety: {
    scope_guard_status: "missing_scope",
    blocked_actions: ["execute_live_validation", "submit_report"],
  },
});

const candidates = toStudioCandidateCards([]);

export default function StudioPage() {
  return (
    <main className="min-h-screen bg-[#f7f7f4] text-[#151515]">
      <div className="mx-auto grid max-w-7xl gap-4 px-6 py-6 lg:grid-cols-[260px_1fr_360px]">
        <aside className="border border-[#d8d6cf] bg-white p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.08em] text-[#62615c]">
            Workspaces
          </p>
          <h1 className="mt-3 text-2xl font-semibold">{workspace.name}</h1>
          <dl className="mt-5 space-y-3 text-sm">
            <div>
              <dt className="text-[#62615c]">Scope Guard</dt>
              <dd className="font-medium">{workspace.scopeGuardLabel}</dd>
            </div>
            <div>
              <dt className="text-[#62615c]">Artifacts</dt>
              <dd className="font-medium">{workspace.artifactCount}</dd>
            </div>
          </dl>
          <Link className="mt-6 inline-block text-sm font-semibold underline" href="/">
            Back to dashboard
          </Link>
        </aside>

        <section className="border border-[#d8d6cf] bg-white p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.08em] text-[#62615c]">
            Conversation
          </p>
          <div className="mt-4 rounded border border-[#e5e2d9] bg-[#fbfaf7] p-4 text-sm">
            Import an authorized policy, scope, API/HAR artifact, and local repo. Then ask
            Mythos Studio to start research. Candidate output remains hypothesis-only until
            evidence review.
          </div>
          <div className="mt-4 rounded border border-dashed border-[#c8c4b8] p-4 text-sm text-[#62615c]">
            Try: Start research, prioritize access control and role boundary issues.
          </div>
        </section>

        <aside className="space-y-4">
          <section className="border border-[#d8d6cf] bg-white p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-[#62615c]">
              Candidate Board
            </p>
            {candidates.length === 0 ? (
              <p className="mt-4 text-sm text-[#62615c]">
                No candidates yet. Run a scoped research pass to generate the top 1-5
                submission-blocked candidates.
              </p>
            ) : null}
          </section>

          <section className="border border-[#d8d6cf] bg-white p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-[#62615c]">
              Safety and Run Log
            </p>
            <ul className="mt-4 space-y-2 text-sm">
              {workspace.blockedActions.map((action) => (
                <li key={action} className="rounded bg-[#f4ece8] px-3 py-2">
                  Blocked: {action}
                </li>
              ))}
            </ul>
          </section>
        </aside>
      </div>
    </main>
  );
}
```

- [x] **Step 4: Run frontend tests**

Run:

```powershell
cd apps/web
npm test -- lib/studio-data.test.ts
```

Expected: tests pass.

---

## Task 5: Local Desktop Launcher

**Files:**
- Create: `apps/studio/package.json`
- Create: `apps/studio/main.cjs`
- Create: `apps/studio/README.md`

- [x] **Step 1: Create the Electron package**

Create `apps/studio/package.json`:

```json
{
  "name": "@bounty-mythos/studio",
  "version": "0.1.0",
  "private": true,
  "main": "main.cjs",
  "scripts": {
    "start": "electron ."
  },
  "devDependencies": {
    "electron": "^43.0.0"
  }
}
```

- [x] **Step 2: Add the desktop launcher main process**

Create `apps/studio/main.cjs`:

```javascript
const { app, BrowserWindow } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");

const root = path.resolve(__dirname, "..", "..");
const children = [];

function spawnChild(command, args, cwd) {
  const child = spawn(command, args, {
    cwd,
    shell: true,
    env: {
      ...process.env,
      DATABASE_URL: process.env.DATABASE_URL || "sqlite:///./bounty_mythos_studio.db",
      REDIS_URL: process.env.REDIS_URL || "redis://localhost:6379/0",
      NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000",
      API_BASE_URL: process.env.API_BASE_URL || "http://localhost:8000",
    },
    stdio: "inherit",
  });
  children.push(child);
  return child;
}

function startServices() {
  spawnChild("python", ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"], path.join(root, "apps", "api"));
  spawnChild("npm", ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", "3000"], path.join(root, "apps", "web"));
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 920,
    title: "Mythos Studio",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadURL("http://127.0.0.1:3000/studio");
}

app.whenReady().then(() => {
  startServices();
  setTimeout(createWindow, 4500);
});

app.on("window-all-closed", () => {
  for (const child of children) {
    child.kill();
  }
  app.quit();
});
```

- [x] **Step 3: Add launcher instructions**

Create `apps/studio/README.md`:

```markdown
# Mythos Studio Launcher

This package opens Mythos Studio as a local desktop app.

It starts the local FastAPI backend and Next.js Studio surface, then opens `/studio` inside an Electron window.

## Development

```powershell
cd apps/api
python -m pip install -r requirements.txt

cd ../web
npm install

cd ../studio
npm install
npm start
```

Safety boundaries remain unchanged: the launcher does not enable public-target attacks, destructive validation, real-user-data handling, raw secret storage, or automatic report submission.
```

- [x] **Step 4: Smoke-test package installation**

Run:

```powershell
cd apps/studio
npm install --package-lock-only
```

Expected: `package-lock.json` is created and npm exits 0.

---

## Task 6: Documentation and Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/product/north-star.md`

- [x] **Step 1: Update README entrypoint**

In `README.md`, add this under `Product Direction`:

```markdown
Preferred local software entrypoint: Mythos Studio. During development, run it from `apps/studio` after installing API and web dependencies. The Studio launcher opens the local `/studio` workspace without making the browser dashboard the primary experience.
```

- [x] **Step 2: Update north-star verification note**

In `docs/product/north-star.md`, add this sentence to `Preferred Product Form`:

```markdown
The first implementation milestone is the local `/studio` workspace plus the Electron launcher in `apps/studio`.
```

- [x] **Step 3: Run targeted verification**

Run:

```powershell
cd apps/api
python -m pytest tests/test_studio_workspace.py tests/test_studio_api.py -q
```

Expected: all Studio API tests pass.

Run:

```powershell
cd apps/web
npm test -- lib/studio-data.test.ts
```

Expected: Studio mapper and page structure tests pass.

Run:

```powershell
cd apps/studio
npm install --package-lock-only
```

Expected: npm exits 0 and keeps the Electron package lock current.

- [x] **Step 4: Final safety grep**

Run:

```powershell
rg -n "submit_report|execute_live_validation|touch_real_user_data|auto_submit" apps/api/app/studio_workspace.py apps/api/app/main.py apps/web/app/studio/page.tsx apps/studio/main.cjs
```

Expected: blocked action names appear only as safety labels or false flags. No code path should submit a report, execute live validation, or collect real user data.

---

## Self-Review

- Spec coverage: This plan implements the local workspace, artifact intake, candidate view, conversation-first Studio surface, safety log, report-oriented output path, and desktop launcher required by the Mythos Studio design.
- Scope control: The plan intentionally does not implement autonomous online validation, fuzzing, or public-target testing.
- Type consistency: Backend workspace names use `StudioWorkspace`, `StudioArtifactImport`, and manifest dictionaries. Frontend names use `StudioWorkspaceSummary` and `StudioCandidateCard`.
- Placeholder scan: The plan contains no placeholder tokens or unspecified implementation steps.
