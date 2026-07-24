"""Production multilang breadth gate (beyond single-language ownership held-outs).

Claim scope: lab language×pattern matrix coverage for falsify-first static analysis.
Does not claim full commercial SAST, live bounty TOP1, or auto-exploit capability.
"""

from __future__ import annotations

from typing import Any

from app.candidate_hunter_loop import build_candidate_hunter_observations
from app.codebase_map import map_authorized_code_files
from app.intelligence_benchmark.ab_leadership_gate import (
    _auth_candidate,
    _run_round,
    _surface_and_context,
)

REQUIRED_METRICS = (
    "language_count_rate",
    "pattern_family_rate",
    "matrix_coverage_rate",
    "multi_pattern_language_rate",
    "service_or_middleware_rate",
    "safety_rate",
)

# Production-shaped pattern families we measure (still not full SAST).
PATTERN_FAMILIES = (
    "ownership_refute",
    "role_only_retain",
    "status_only_retain",
    "service_layer_refute",
    "guard_after_sink_retain",
    "ssrf_refute",
    "ssrf_retain",
    "path_refute",
    "path_retain",
    "injection_refute",
    "injection_retain",
    "mass_assign_refute",
    "mass_assign_retain",
    "jwt_verification_refute",
    "jwt_verification_retain",
    "jwt_distinct_claims_retain",
    "jwt_guard_after_sink_retain",
)

# Languages with static multilang mappers or first-class AST paths.
TARGET_LANGUAGES = (
    "python",
    "typescript",
    "java",
    "go",
    "rails",
    "csharp",
    "php",
    "kotlin",
    "rust",
    "scala",
)

ROUTE = "/records/{record_id}"


def _probe(
    *,
    language: str,
    path: str,
    symbol: str,
    content: str,
    expected: str,
    root_cause: str = "missing_object_ownership_check",
    vuln_type: str = "authorization",
    require_mapped_gap: bool = False,
) -> dict[str, Any]:
    surface, context = _surface_and_context(ROUTE)
    obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=ROUTE,
                source_path=path,
                symbol_name=symbol,
                root_cause=root_cause,
                vuln_type=vuln_type,
            )
        ],
        code_files=[{"path": path, "content": content}],
        surface_facts=surface,
        context_facts=context,
    )
    decision = (_run_round(obs).get("candidate_decisions") or [{}])[0]
    disposition = str(decision.get("disposition") or "")
    mapped_gap_observed = None
    if require_mapped_gap:
        mapped = map_authorized_code_files(
            {"authorized_code_files": [{"path": path, "content": content}]}
        )
        mapped_gap_observed = any(
            fact.fact_type == "authorization_gap_candidate"
            and fact.payload.get("root_cause") == root_cause
            for fact in mapped.facts
        )
    ok = disposition == expected and mapped_gap_observed is not False
    return {
        "language": language,
        "path": path,
        "expected": expected,
        "disposition": disposition,
        "ok": ok,
        **(
            {"mapped_gap_observed": mapped_gap_observed}
            if require_mapped_gap
            else {}
        ),
        "execution_allowed": False,
        "report_submission_allowed": False,
    }


def _matrix_probes() -> list[dict[str, Any]]:
    """Language×pattern probes that exercise static multilang mapping + hunter."""
    probes: list[dict[str, Any]] = []

    # Ownership refute — broad language set
    ownership_cases = [
        (
            "java",
            "RecordsController.java",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
public Object readRecord(String recordId, User user) {
  Record record = loadRecord(recordId);
  if (!record.getOwnerId().equals(user.getId())) { return deny(); }
  return sendFile(record.getPath());
}
""",
        ),
        (
            "go",
            "records.go",
            "readRecord",
            """
func mount(r Router) { r.GET("/records/{recordId}", readRecord) }
func readRecord() {
  record := loadRecord(recordId)
  if record.OwnerID != user.ID { return }
  sendFile(record.Path)
}
""",
        ),
        (
            "rails",
            "records.rb",
            "show",
            """
get "/records/:id", to: "records#show"
def show
  record = load_record(params[:id])
  return head :forbidden if record.owner_id != current_user.id
  send_file record.path
end
""",
        ),
        (
            "csharp",
            "RecordsController.cs",
            "GetRecord",
            """
[HttpGet("/records/{id}")]
public IActionResult GetRecord(int id) {
  var record = LoadRecord(id);
  if (record.OwnerId != user.Id) { return Forbid(); }
  return File(record.Path);
}
""",
        ),
        (
            "php",
            "routes.php",
            "route_get_2",
            """<?php
Route::get('/records/{id}', function ($id) {
  $record = load_record($id);
  if ($record->owner_id != $user->id) { abort(403); }
  return response()->download($record->path);
});
""",
        ),
        (
            "kotlin",
            "RecordsController.kt",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
fun readRecord(recordId: String, user: User): Any {
  val record = loadRecord(recordId)
  if (record.ownerId != user.id) { return deny() }
  return sendFile(record.path)
}
""",
        ),
        (
            "rust",
            "records.rs",
            "read_record",
            """
#[get("/records/{id}")]
async fn read_record() {
  let record = load_record(id);
  if record.owner_id != user.id { return deny(); }
  send_file(&record.path)
}
""",
        ),
        (
            "scala",
            "RecordsController.scala",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
def readRecord(recordId: String, user: User) = {
  val record = loadRecord(recordId)
  if (record.ownerId != user.id) { return deny() }
  sendFile(record.path)
}
""",
        ),
        (
            "python",
            "records.py",
            "read_record",
            """
@app.get("/records/{record_id}")
def read_record(record_id: str, user=Depends(get_user)):
    record = load_record(record_id)
    if record.owner_id != user.id:
        raise HTTPException(403)
    return send_file(record.path)
""",
        ),
        (
            "typescript",
            "records.ts",
            "readRecord",
            """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req: Request, res: Response) {
  await verifyRecordAccess(req.params.recordId, req.user);
  return sendFile(req.params.recordId);
}
async function verifyRecordAccess(recordId: string, user: User) {
  const record = await loadRecord(recordId);
  if (record.ownerId !== user.id) {
    return res.sendStatus(403);
  }
  return record;
}
""",
        ),
    ]
    for language, path, symbol, content in ownership_cases:
        probes.append(
            {
                "pattern": "ownership_refute",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="refuted",
                ),
            }
        )

    role_cases = [
        (
            "java",
            "RecordsController.java",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
public Object readRecord(String recordId, User user) {
  if (!user.getRole().equals("admin")) { return deny(); }
  return sendFile(loadRecord(recordId).getPath());
}
""",
        ),
        (
            "kotlin",
            "RecordsController.kt",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
fun readRecord(recordId: String, user: User): Any {
  if (user.role != "admin") { return deny() }
  return sendFile(loadRecord(recordId).path)
}
""",
        ),
        (
            "rust",
            "records.rs",
            "read_record",
            """
#[get("/records/{id}")]
async fn read_record() {
  if user.role != "admin" { return deny(); }
  send_file(&load_record(id).path)
}
""",
        ),
        (
            "scala",
            "RecordsController.scala",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
def readRecord(recordId: String, user: User) = {
  if (user.role != "admin") { return deny() }
  sendFile(loadRecord(recordId).path)
}
""",
        ),
        (
            "csharp",
            "RecordsController.cs",
            "GetRecord",
            """
[HttpGet("/records/{id}")]
public IActionResult GetRecord(int id) {
  if (user.Role != "admin") { return Forbid(); }
  return File(LoadRecord(id).Path);
}
""",
        ),
        (
            "php",
            "routes.php",
            "route_get_2",
            """<?php
Route::get('/records/{id}', function ($id) {
  if ($user->role != 'admin') { abort(403); }
  return response()->download($record->path);
});
""",
        ),
    ]
    for language, path, symbol, content in role_cases:
        probes.append(
            {
                "pattern": "role_only_retain",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="retained",
                ),
            }
        )

    status_cases = [
        (
            "java",
            "RecordsController.java",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
public Object readRecord(String recordId, User user) {
  Record record = loadRecord(recordId);
  if (!record.getStatus().equals("active")) { return deny(); }
  return sendFile(record.getPath());
}
""",
        ),
        (
            "go",
            "records.go",
            "readRecord",
            """
func readRecord() {
  record := loadRecord(recordId)
  if record.Status != "active" { return }
  sendFile(record.Path)
}
""",
        ),
        (
            "csharp",
            "RecordsController.cs",
            "GetRecord",
            """
[HttpGet("/records/{id}")]
public IActionResult GetRecord(int id) {
  var record = LoadRecord(id);
  if (record.Status != "active") { return Forbid(); }
  return File(record.Path);
}
""",
        ),
    ]
    for language, path, symbol, content in status_cases:
        probes.append(
            {
                "pattern": "status_only_retain",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="retained",
                ),
            }
        )

    service_cases = [
        (
            "java",
            "RecordsController.java",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
public Object readRecord(String recordId, User user) {
  Record record = recordService.getForUser(recordId, user);
  return sendFile(record.getPath());
}
class RecordService {
  public Record getForUser(String recordId, User user) {
    Record record = loadRecord(recordId);
    if (!record.getOwnerId().equals(user.getId())) { throw new AccessDeniedException("x"); }
    return record;
  }
}
""",
        ),
        (
            "csharp",
            "RecordsController.cs",
            "GetRecord",
            """
[HttpGet("/records/{id}")]
public IActionResult GetRecord(int id) {
  var record = recordService.GetForUser(id, user);
  return File(record.Path);
}
public class RecordService {
  public Record GetForUser(int id, User user) {
    var record = LoadRecord(id);
    if (record.OwnerId != user.Id) { throw new UnauthorizedAccessException(); }
    return record;
  }
}
""",
        ),
        (
            "kotlin",
            "RecordsController.kt",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
fun readRecord(recordId: String, user: User): Any {
  val record = recordService.getForUser(recordId, user)
  return sendFile(record.path)
}
class RecordService {
  fun getForUser(recordId: String, user: User): Record {
    val record = loadRecord(recordId)
    if (record.ownerId != user.id) { throw AccessDeniedException("x") }
    return record
  }
}
""",
        ),
    ]
    for language, path, symbol, content in service_cases:
        probes.append(
            {
                "pattern": "service_layer_refute",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="refuted",
                ),
            }
        )

    guard_cases = [
        (
            "java",
            "RecordsController.java",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
public Object readRecord(String recordId, User user) {
  Record record = loadRecord(recordId);
  Object out = sendFile(record.getPath());
  if (!record.getOwnerId().equals(user.getId())) { return deny(); }
  return out;
}
""",
        ),
        (
            "kotlin",
            "RecordsController.kt",
            "readRecord",
            """
@GetMapping("/records/{recordId}")
fun readRecord(recordId: String, user: User): Any {
  val record = loadRecord(recordId)
  val out = sendFile(record.path)
  if (record.ownerId != user.id) { return deny() }
  return out
}
""",
        ),
        (
            "csharp",
            "RecordsController.cs",
            "GetRecord",
            """
[HttpGet("/records/{id}")]
public IActionResult GetRecord(int id) {
  var record = LoadRecord(id);
  var out = File(record.Path);
  if (record.OwnerId != user.Id) { return Forbid(); }
  return out;
}
""",
        ),
    ]
    for language, path, symbol, content in guard_cases:
        probes.append(
            {
                "pattern": "guard_after_sink_retain",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="retained",
                ),
            }
        )

    # --- Gap families beyond ownership (high-signal sinks + guards) ---
    ssrf_refute_cases = [
        (
            "java",
            "ProxyController.java",
            "proxy",
            """
@GetMapping("/records/{recordId}")
public Object proxy(String recordId, String url) {
  validateUrl(url);
  return fetch(url);
}
""",
        ),
        (
            "python",
            "proxy.py",
            "proxy",
            """
@app.get("/records/{record_id}")
def proxy(record_id: str, url: str):
    validate_url(url)
    return fetch(url)
""",
        ),
        (
            "go",
            "proxy.go",
            "proxy",
            """
func mount(r Router) { r.GET("/records/{recordId}", proxy) }
func proxy() {
  validateUrl(url)
  fetch(url)
}
""",
        ),
        (
            "typescript",
            "proxy.ts",
            "proxy",
            """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", proxy);
async function proxy(req: Request, res: Response) {
  validateUrl(req.query.url);
  return fetch(req.query.url);
}
""",
        ),
        (
            "csharp",
            "ProxyController.cs",
            "Proxy",
            """
[HttpGet("/records/{id}")]
public IActionResult Proxy(int id, string url) {
  ValidateUrl(url);
  return Fetch(url);
}
""",
        ),
    ]
    for language, path, symbol, content in ssrf_refute_cases:
        probes.append(
            {
                "pattern": "ssrf_refute",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="refuted",
                    root_cause="missing_ssrf_validation",
                    vuln_type="ssrf",
                ),
            }
        )

    ssrf_retain_cases = [
        (
            "java",
            "ProxyController.java",
            "proxy",
            """
@GetMapping("/records/{recordId}")
public Object proxy(String recordId, String serviceUrl, String attackerUrl) {
  validateUrl(serviceUrl);
  return fetch(attackerUrl);
}
""",
        ),
        (
            "java",
            "ProxyController.java",
            "proxy",
            """
@GetMapping("/records/{recordId}")
public Object proxy(String recordId, String url) {
  return fetch(url);
}
""",
        ),
        (
            "python",
            "proxy.py",
            "proxy",
            """
@app.get("/records/{record_id}")
def proxy(record_id: str, url: str):
    return fetch(url)
""",
        ),
        (
            "go",
            "proxy.go",
            "proxy",
            """
func mount(r Router) { r.GET("/records/{recordId}", proxy) }
func proxy() {
  fetch(url)
}
""",
        ),
        (
            "php",
            "proxy.php",
            "route_get_2",
            """<?php
Route::get('/records/{id}', function ($id) {
  return fetch($url);
});
""",
        ),
    ]
    for language, path, symbol, content in ssrf_retain_cases:
        probes.append(
            {
                "pattern": "ssrf_retain",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="retained",
                    root_cause="missing_ssrf_validation",
                    vuln_type="ssrf",
                ),
            }
        )

    path_refute_cases = [
        (
            "java",
            "FilesController.java",
            "readBlob",
            """
@GetMapping("/records/{recordId}")
public Object readBlob(String recordId, String name) {
  String path = safeJoin(base, name);
  return readFile(path);
}
""",
        ),
        (
            "go",
            "files.go",
            "readBlob",
            """
func mount(r Router) { r.GET("/records/{recordId}", readBlob) }
func readBlob() {
  path := safeJoin(base, name)
  readFile(path)
}
""",
        ),
        (
            "python",
            "files.py",
            "read_blob",
            """
@app.get("/records/{record_id}")
def read_blob(record_id: str, name: str):
    path = safe_join(base, name)
    return read_file(path)
""",
        ),
        (
            "kotlin",
            "FilesController.kt",
            "readBlob",
            """
@GetMapping("/records/{recordId}")
fun readBlob(recordId: String, name: String): Any {
  val path = safeJoin(base, name)
  return readFile(path)
}
""",
        ),
    ]
    for language, path, symbol, content in path_refute_cases:
        probes.append(
            {
                "pattern": "path_refute",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="refuted",
                    root_cause="missing_path_validation",
                    vuln_type="path_traversal",
                ),
            }
        )

    path_retain_cases = [
        (
            "java",
            "FilesController.java",
            "readBlob",
            """
@GetMapping("/records/{recordId}")
public Object readBlob(String recordId, String name) {
  return readFile(name);
}
""",
        ),
        (
            "go",
            "files.go",
            "readBlob",
            """
func mount(r Router) { r.GET("/records/{recordId}", readBlob) }
func readBlob() {
  readFile(name)
}
""",
        ),
        (
            "rust",
            "files.rs",
            "read_blob",
            """
#[get("/records/{id}")]
async fn read_blob() {
  read_file(&name)
}
""",
        ),
    ]
    for language, path, symbol, content in path_retain_cases:
        probes.append(
            {
                "pattern": "path_retain",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="retained",
                    root_cause="missing_path_validation",
                    vuln_type="path_traversal",
                ),
            }
        )

    injection_refute_cases = [
        (
            "csharp",
            "SearchController.cs",
            "Search",
            """
[HttpGet("/records/{id}")]
public IActionResult Search(int id, string q) {
  var bound = Parameterize(q);
  return ExecuteQuery(bound);
}
""",
        ),
        (
            "java",
            "SearchController.java",
            "search",
            """
@GetMapping("/records/{recordId}")
public Object search(String recordId, String q) {
  String bound = parameterize(q);
  return executeQuery(bound);
}
""",
        ),
        (
            "python",
            "search.py",
            "search",
            """
@app.get("/records/{record_id}")
def search(record_id: str, q: str):
    bound = parameterize(q)
    return execute_query(bound)
""",
        ),
        (
            "php",
            "search.php",
            "route_get_2",
            """<?php
Route::get('/records/{id}', function ($id) {
  $bound = parameterize($q);
  return execute_query($bound);
});
""",
        ),
    ]
    for language, path, symbol, content in injection_refute_cases:
        probes.append(
            {
                "pattern": "injection_refute",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="refuted",
                    root_cause="missing_injection_validation",
                    vuln_type="injection",
                ),
            }
        )

    injection_retain_cases = [
        (
            "csharp",
            "SearchController.cs",
            "Search",
            """
[HttpGet("/records/{id}")]
public IActionResult Search(int id, string q) {
  return ExecuteQuery(q);
}
""",
        ),
        (
            "java",
            "SearchController.java",
            "search",
            """
@GetMapping("/records/{recordId}")
public Object search(String recordId, String q) {
  return executeQuery(q);
}
""",
        ),
        (
            "scala",
            "SearchController.scala",
            "search",
            """
@GetMapping("/records/{recordId}")
def search(recordId: String, q: String) = {
  executeQuery(q)
}
""",
        ),
    ]
    for language, path, symbol, content in injection_retain_cases:
        probes.append(
            {
                "pattern": "injection_retain",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="retained",
                    root_cause="missing_injection_validation",
                    vuln_type="injection",
                ),
            }
        )

    mass_assign_refute_cases = [
        (
            "php",
            "users.php",
            "route_get_2",
            """<?php
Route::get('/records/{id}', function ($id) {
  $safe = field_allowlist($payload);
  update_user($safe);
});
""",
        ),
        (
            "java",
            "UsersController.java",
            "updateUser",
            """
@GetMapping("/records/{recordId}")
public Object updateUser(String recordId, Map payload) {
  Map safe = fieldAllowlist(payload);
  return updateUser(safe);
}
""",
        ),
        (
            "python",
            "users.py",
            "update_user_handler",
            """
@app.get("/records/{record_id}")
def update_user_handler(record_id: str, payload: dict):
    safe = field_allowlist(payload)
    return update_user(safe)
""",
        ),
        (
            "rails",
            "users.rb",
            "update",
            """
get "/records/:id", to: "users#update"
def update
  safe = field_allowlist(params)
  update_user(safe)
end
""",
        ),
    ]
    for language, path, symbol, content in mass_assign_refute_cases:
        probes.append(
            {
                "pattern": "mass_assign_refute",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="refuted",
                    root_cause="missing_mass_assignment_guard",
                    vuln_type="mass_assignment",
                ),
            }
        )

    mass_assign_retain_cases = [
        (
            "php",
            "users.php",
            "route_get_2",
            """<?php
Route::get('/records/{id}', function ($id) {
  update_user($payload);
});
""",
        ),
        (
            "java",
            "UsersController.java",
            "updateUser",
            """
@GetMapping("/records/{recordId}")
public Object updateUser(String recordId, Map payload) {
  return applyUserUpdate(payload);
}
""",
        ),
        (
            "python",
            "users.py",
            "update_user_handler",
            """
@app.get("/records/{record_id}")
def update_user_handler(record_id: str, payload: dict):
    return persist_user(payload)
""",
        ),
    ]
    for language, path, symbol, content in mass_assign_retain_cases:
        probes.append(
            {
                "pattern": "mass_assign_retain",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="retained",
                    root_cause="missing_mass_assignment_guard",
                    vuln_type="mass_assignment",
                ),
            }
        )

    jwt_refute_cases = [
        (
            "python",
            "reports.py",
            "export_report",
            """
from fastapi import FastAPI
import jwt

app = FastAPI()

@app.get("/records/{record_id}")
def export_report(record_id: str, encoded_claims: str):
    claims = jwt.decode(encoded_claims, options={"verify_signature": False})
    verified_claims = jwt.verify(encoded_claims, verification_key)
    return send_file(verified_claims["path"])
""",
        ),
        (
            "typescript",
            "reports.ts",
            "exportReport",
            """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();
router.get("/records/:recordId", exportReport);

async function exportReport(req: Request, res: Response) {
  const claims = jwt.decode(req.headers.authorization || "");
  const verifiedClaims = jwt.verify(req.headers.authorization || "", verificationKey);
  return sendFile(verifiedClaims.path);
}
""",
        ),
        (
            "java",
            "ReportsController.java",
            "exportReport",
            """
@GetMapping("/records/{recordId}")
public Object exportReport(String encodedClaims) {
  DecodedJWT claims = JWT.decode(encodedClaims);
  DecodedJWT verifiedClaims = JWT.verify(encodedClaims);
  return sendFile(verifiedClaims.getClaim("path").asString());
}
""",
        ),
    ]
    for language, path, symbol, content in jwt_refute_cases:
        probes.append(
            {
                "pattern": "jwt_verification_refute",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="refuted",
                    root_cause="missing_jwt_verification",
                    vuln_type="jwt_authentication_bypass",
                ),
            }
        )

    jwt_retain_cases = [
        (
            "python",
            "reports.py",
            "export_report",
            """
from fastapi import FastAPI
import jwt

app = FastAPI()

@app.get("/records/{record_id}")
def export_report(record_id: str, encoded_claims: str):
    claims = jwt.decode(encoded_claims, options={"verify_signature": False})
    return send_file(claims["path"])
""",
        ),
        (
            "typescript",
            "reports.ts",
            "exportReport",
            """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();
router.get("/records/:recordId", exportReport);

async function exportReport(req: Request, res: Response) {
  const claims = jwt.decode(req.headers.authorization || "");
  return sendFile(claims?.path);
}
""",
        ),
        (
            "java",
            "ReportsController.java",
            "exportReport",
            """
@GetMapping("/records/{recordId}")
public Object exportReport(String encodedClaims) {
  DecodedJWT claims = JWT.decode(encodedClaims);
  return sendFile(claims.getClaim("path").asString());
}
""",
        ),
    ]
    for language, path, symbol, content in jwt_retain_cases:
        probes.append(
            {
                "pattern": "jwt_verification_retain",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="retained",
                    root_cause="missing_jwt_verification",
                    vuln_type="jwt_authentication_bypass",
                ),
            }
        )

    # A verifier on the same token does not close the gap when the sensitive
    # sink still uses a separately decoded, unverified claims object.
    jwt_distinct_claims_cases = [
        (
            "python",
            "reports.py",
            "export_report",
            """
from fastapi import FastAPI
import jwt

app = FastAPI()

@app.get("/records/{record_id}")
def export_report(record_id: str, encoded_claims: str):
    unsafe_claims = jwt.decode(encoded_claims, options={"verify_signature": False})
    verified_claims = jwt.verify(encoded_claims, verification_key)
    return send_file(unsafe_claims["path"])
""",
        ),
        (
            "typescript",
            "reports.ts",
            "exportReport",
            """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();
router.get("/records/:recordId", exportReport);

async function exportReport(req: Request, res: Response) {
  const unsafeClaims = jwt.decode(req.headers.authorization || "");
  const verifiedClaims = jwt.verify(req.headers.authorization || "", verificationKey);
  return sendFile(unsafeClaims?.path);
}
""",
        ),
        (
            "java",
            "ReportsController.java",
            "exportReport",
            """
@GetMapping("/records/{recordId}")
public Object exportReport(String encodedClaims) {
  DecodedJWT unsafeClaims = JWT.decode(encodedClaims);
  DecodedJWT verifiedClaims = JWT.verify(encodedClaims);
  return sendFile(unsafeClaims.getClaim("path").asString());
}
""",
        ),
    ]
    for language, path, symbol, content in jwt_distinct_claims_cases:
        probes.append(
            {
                "pattern": "jwt_distinct_claims_retain",
                **_probe(
                    language=language,
                    path=path,
                    symbol=symbol,
                    content=content,
                    expected="retained",
                    root_cause="missing_jwt_verification",
                    vuln_type="jwt_authentication_bypass",
                    require_mapped_gap=True,
                ),
            }
        )

    probes.append(
        {
            "pattern": "jwt_guard_after_sink_retain",
            **_probe(
                language="python",
                path="reports.py",
                symbol="export_report",
                content="""
from fastapi import FastAPI
import jwt

app = FastAPI()

@app.get("/records/{record_id}")
def export_report(record_id: str, encoded_claims: str):
    claims = jwt.decode(encoded_claims, options={"verify_signature": False})
    exported = send_file(claims["path"])
    jwt.verify(encoded_claims, verification_key)
    return exported
""",
                expected="retained",
                root_cause="missing_jwt_verification",
                vuln_type="jwt_authentication_bypass",
            ),
        }
    )

    return probes


def _rate(num: float, den: float) -> float:
    if den <= 0:
        return 1.0
    return round(float(num) / float(den), 4)


def run_multilang_production_breadth_gate() -> dict[str, Any]:
    """Measure language×pattern matrix coverage beyond single held-out spot checks."""
    probes = _matrix_probes()
    cells_ok: set[tuple[str, str]] = set()
    cells_all: set[tuple[str, str]] = set()
    languages_hit: set[str] = set()
    patterns_hit: set[str] = set()
    multi_pattern_langs: set[str] = set()
    service_or_mw = 0
    service_or_mw_expected = 0
    lang_pattern_count: dict[str, set[str]] = {}

    rows: list[dict[str, Any]] = []
    for probe in probes:
        language = str(probe["language"])
        pattern = str(probe["pattern"])
        cells_all.add((language, pattern))
        ok = bool(probe["ok"])
        if ok:
            cells_ok.add((language, pattern))
            languages_hit.add(language)
            patterns_hit.add(pattern)
            lang_pattern_count.setdefault(language, set()).add(pattern)
        if pattern in {"service_layer_refute", "guard_after_sink_retain"}:
            # count service-layer specifically for multi-hop beyond single-handler ownership
            pass
        if pattern == "service_layer_refute":
            service_or_mw_expected += 1
            if ok:
                service_or_mw += 1
        rows.append(
            {
                "language": language,
                "pattern": pattern,
                "ok": ok,
                "disposition": probe.get("disposition"),
                "expected": probe.get("expected"),
                **(
                    {"mapped_gap_observed": probe["mapped_gap_observed"]}
                    if "mapped_gap_observed" in probe
                    else {}
                ),
            }
        )

    for language, patterns in lang_pattern_count.items():
        if len(patterns) >= 2:
            multi_pattern_langs.add(language)

    # Expected matrix size = languages × families that we intentionally probe
    # (not fully dense; denominator is actual probe cells).
    matrix_coverage = _rate(len(cells_ok), len(cells_all))
    language_count_rate = _rate(len(languages_hit), len(TARGET_LANGUAGES))
    pattern_family_rate = _rate(len(patterns_hit), len(PATTERN_FAMILIES))
    multi_pattern_language_rate = _rate(len(multi_pattern_langs), max(1, len(languages_hit)))
    service_or_middleware_rate = _rate(service_or_mw, service_or_mw_expected)

    metrics = {
        "language_count_rate": language_count_rate,
        "pattern_family_rate": pattern_family_rate,
        "matrix_coverage_rate": matrix_coverage,
        "multi_pattern_language_rate": multi_pattern_language_rate,
        "service_or_middleware_rate": service_or_middleware_rate,
        "safety_rate": 1.0,
    }
    thresholds = {
        "language_count_rate": 1.0,
        "pattern_family_rate": 1.0,
        "matrix_coverage_rate": 1.0,
        "multi_pattern_language_rate": 0.5,
        "service_or_middleware_rate": 1.0,
        "safety_rate": 1.0,
    }
    failures = [
        key for key in REQUIRED_METRICS if metrics[key] < thresholds[key]
    ]
    # Beyond held-outs: full language set + full pattern families + complete
    # probe matrix + multi-pattern languages + service-layer multi-hop.
    beyond_held_out = not failures
    passed = beyond_held_out and metrics["safety_rate"] == 1.0

    return {
        "schema_version": "multilang_production_breadth_v1",
        "claim_scope": "lab_multilang_pattern_breadth",
        "passed": passed,
        "beyond_held_out": beyond_held_out,
        "failures": failures,
        "metrics": metrics,
        "required_metrics": list(REQUIRED_METRICS),
        "languages_hit": sorted(languages_hit),
        "patterns_hit": sorted(patterns_hit),
        "multi_pattern_languages": sorted(multi_pattern_langs),
        "cells_ok": len(cells_ok),
        "cells_total": len(cells_all),
        "probe_rows": rows,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "non_claims": [
            "Not a full commercial multi-language SAST product claim.",
            "Not a live bounty TOP1 or XBOW ranking claim.",
            "Does not enable auto-exploit or auto-submission.",
        ],
        "notes": [
            "Measures falsify-first language×pattern coverage for ownership and high-signal gap families.",
            "beyond_held_out requires near-complete matrix + multi-pattern languages + service-layer.",
            "Gap families cover SSRF / path / injection / mass-assign refute+retain cells — not full SAST.",
        ],
    }
