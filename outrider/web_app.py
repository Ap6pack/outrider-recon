import secrets
import threading
import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from outrider import web_view
from outrider import bridge
from outrider.evidence import (EvidenceRefusalError, EvidenceValidationError, evidence_revision, list_artifact_candidates, load_evidence_registry, normalize_evidence_path, register_evidence, verify_all_evidence)
from outrider.approval import (
    ACTION_TYPES, APPROVABLE, ApprovalPolicyError, ApprovalValidationError,
    approval_revision, evaluate_action, grant_approval, list_approvals, revoke_approval,
)
from outrider.state import InvalidTransitionError, StateValidationError, load_manifest, load_state, transition_state
from outrider.workflow_guide import GUIDE_ACTION_TARGETS, build_workflow_guide
from outrider.scope import ScopeValidationError, evaluate_scope, load_scope, replace_scope_rules_atomic, scope_revision
from outrider.run_setup import PLATFORM_OPTIONS, RunConflictError, RunSetupError, WebRunRequest, create_web_run_atomic
from outrider.skill_contract import (REQUEST_ACTIONS, SkillContractValidationError, contract_revision, create_skill_request, find_skill_request_by_id, find_skill_result_by_id, list_known_skills, load_skill_request, load_skill_result, validate_skill_request, validate_skill_result)
from outrider.finding import (PROMOTED_CONFIDENCES, SEVERITIES, VALIDATION_BASES, FindingPromotionRefusal, FindingValidationError, finding_revision, promote_finding_by_ids, verify_all_findings)
from outrider.mcp_enrichment import EnrichmentError, InputError, FixedEnrichmentExecutor, catalog as mcp_catalog, preflight as mcp_preflight, invoke as mcp_invoke, _SCOPE_NOTE, _NOTICE

TOKEN_HEADER = "X-Outrider-Control-Token"


def _capabilities(mcp_enrichment_enabled: bool) -> dict:
    return {"state_transition": True, "run_creation": True, "web_first_launcher": True, "engagement_onboarding": True, "engagement_creation": True, "engagement_resume": True, "guided_workflow": True, "next_action_engine": True, "guided_state_progression": True, "automatic_discovery": False, "guided_discovery": False, "automatic_evidence_capture": False, "scope_edit": True, "scope_check": True, "approval_mutation": True, "action_check": True, "artifact_inventory": True, "evidence_registration": True, "evidence_verification": True, "artifact_upload": False, "artifact_download": False, "contract_mutation": True, "contract_request_creation": True, "contract_validation": True, "contract_result_creation": False, "contract_upload": False, "skill_execution": False, "finding_candidate_inventory": True, "finding_promotion": True, "finding_verification": True, "automatic_finding_promotion": False, "finding_edit": False, "finding_delete": False, "mcp_catalog": True, "mcp_preflight": True, "mcp_invocation": mcp_enrichment_enabled, "mcp_enrichment_enabled": mcp_enrichment_enabled, "fixed_outbound_enrichment_tools": 5, "recon_execution": False, "report_generation": False, "legacy_import": True, "materialize": True}

def create_app(runs_root: str | Path, *, control_token: str | None = None, mcp_enrichment_enabled: bool = False, enrichment_executor=None, targets_root: str | Path | None = None):
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.responses import FileResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError('Install web dependencies with: python -m pip install -e ".[web]"') from exc

    root = Path(runs_root)
    targets_dir = Path(targets_root) if targets_root is not None else root.parent / "targets"
    token = control_token if control_token is not None else secrets.token_urlsafe(32)
    mutation_lock = threading.Lock()
    enrichment_executor = enrichment_executor
    enrichment_lock = threading.Lock()
    logger = logging.getLogger(__name__)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, debug=False)
    static_dir = Path(__file__).with_name("web_static")

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        message = exc.detail if isinstance(exc.detail, str) else "request rejected"
        return JSONResponse({"error": message}, status_code=exc.status_code)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def json(payload, status_code: int = 200):
        return JSONResponse(payload, status_code=status_code)

    def error(status_code: int, message: str):
        return json({"error": message}, status_code=status_code)

    def same_origin(request: Request) -> bool:
        origin = request.headers.get("origin")
        if not origin:
            return True
        url = request.url
        host = request.headers.get("host") or url.netloc
        return origin == f"{url.scheme}://{host}"

    def require_mutation_guard(request: Request):
        if request.headers.get(TOKEN_HEADER) != token:
            raise HTTPException(status_code=403, detail="mutation token rejected")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="origin rejected")
        if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
            raise HTTPException(status_code=403, detail="cross-site mutation rejected")

    @app.get("/api/health")
    def health():
        return {"ok": True, "service": "outrider-web", "mode": "limited-control", "network_scope": "loopback-only", "authentication": "none", "capabilities": _capabilities(mcp_enrichment_enabled)}

    @app.get("/api/session")
    def session():
        return json({"mode": "limited-control", "authentication": "none", "control_token": token, "capabilities": _capabilities(mcp_enrichment_enabled)})

    @app.get("/api/onboarding")
    def onboarding():
        inventory = web_view.list_runs(root)
        return json({"first_run": inventory.get("total", 0) == 0, "engagement_count": inventory.get("total", 0), "enrichment_enabled": mcp_enrichment_enabled, "platform_options": list(PLATFORM_OPTIONS), "capabilities": {"engagement_creation": True, "engagement_resume": True, "guided_workflow": True, "next_action_engine": True, "guided_state_progression": True, "automatic_discovery": False, "guided_discovery": False, "automatic_evidence_capture": False}})


    async def read_json_object(request: Request):
        if "application/json" not in request.headers.get("content-type", ""):
            return None, error(422, "JSON body required")
        try:
            body = await request.json()
        except Exception:
            return None, error(422, "malformed JSON")
        if not isinstance(body, dict):
            return None, error(422, "JSON object required")
        return body, None

    @app.post("/api/runs")
    async def create_run(request: Request):
        require_mutation_guard(request)
        body, err = await read_json_object(request)
        if err: return err
        allowed = {"target", "actor", "authorization_reference", "engagement_platform", "traffic_header", "in_scope", "out_of_scope", "confirmed"}
        if set(body) - allowed: return error(422, "unknown field")
        for field in ("target", "actor", "authorization_reference"):
            if not isinstance(body.get(field), str) or not body[field].strip():
                return error(422, f"{field} must be a non-empty string")
        if body.get("confirmed") is not True:
            return error(422, "authorization confirmation is required")
        for field, limit in (("actor", 200), ("authorization_reference", 500)):
            if len(body[field]) > limit or any(ch in body[field] for ch in "\0\r\n"):
                return error(422, f"{field} is invalid")
        if "in_scope" not in body or "out_of_scope" not in body:
            return error(422, "in_scope and out_of_scope are required")
        with mutation_lock:
            try:
                run_dir = create_web_run_atomic(root, WebRunRequest(body["target"], body["actor"], body["authorization_reference"], body["in_scope"], body["out_of_scope"], body.get("engagement_platform"), body.get("traffic_header")))
                manifest = load_manifest(run_dir)
                payload = {"ok": True, "run": web_view.run_overview(run_dir), "scope": web_view.scope_view(run_dir)}
                return JSONResponse(payload, status_code=201, headers={"Location": f"/api/runs/{manifest.run_id}/overview"})
            except RunConflictError:
                return error(409, "An engagement for this target already exists. Resume the existing engagement or use a different target.")
            except (RunSetupError, ScopeValidationError, ValueError) as exc:
                return error(422, str(exc) or "run creation request is invalid")
            except Exception:
                return error(500, "run creation failed")

    @app.get("/api/import/sources")
    def import_sources():
        names = []
        try:
            for child in sorted(targets_dir.iterdir(), key=lambda p: p.name):
                if child.is_dir() and not child.is_symlink():
                    names.append(child.name)
        except OSError:
            names = []
        return json({"base": str(targets_dir), "sources": names})

    @app.post("/api/import-target")
    async def import_target_run(request: Request):
        require_mutation_guard(request)
        body, err = await read_json_object(request)
        if err: return err
        allowed = {"source", "target", "actor", "authorization_reference", "in_scope", "out_of_scope", "engagement_platform", "confirmed"}
        if set(body) - allowed: return error(422, "unknown field")
        for field in ("source", "target", "actor", "authorization_reference"):
            if not isinstance(body.get(field), str) or not body[field].strip():
                return error(422, f"{field} must be a non-empty string")
        if body.get("confirmed") is not True:
            return error(422, "authorization confirmation is required")
        for field, limit in (("actor", 200), ("authorization_reference", 500)):
            if len(body[field]) > limit or any(ch in body[field] for ch in "\0\r\n"):
                return error(422, f"{field} is invalid")
        if "in_scope" not in body or "out_of_scope" not in body:
            return error(422, "in_scope and out_of_scope are required")
        source_dir = bridge.resolve_import_source(targets_dir, body["source"])
        if source_dir is None:
            return error(422, "source must be an existing subdirectory of the targets base")
        with mutation_lock:
            try:
                run_dir = create_web_run_atomic(root, WebRunRequest(body["target"], body["actor"], body["authorization_reference"], body["in_scope"], body["out_of_scope"], body.get("engagement_platform"), None))
            except RunConflictError:
                return error(409, "An engagement for this target already exists. Resume the existing engagement or use a different target.")
            except (RunSetupError, ScopeValidationError, ValueError) as exc:
                return error(422, str(exc) or "run creation request is invalid")
            except Exception:
                return error(500, "run creation failed")
            try:
                summary = bridge.import_files_as_evidence(run_dir, source_dir, actor=body["actor"])
            except Exception:
                return error(500, "import failed after run creation")
            manifest = load_manifest(run_dir)
            payload = {"ok": True, "run": web_view.run_overview(run_dir), "scope": web_view.scope_view(run_dir), "imported": {k: summary[k] for k in ("copied", "registered", "skipped_existing", "skipped_large")}}
            return JSONResponse(payload, status_code=201, headers={"Location": f"/api/runs/{manifest.run_id}/overview"})

    @app.post("/api/runs/{run_id}/materialize")
    async def materialize_run_endpoint(run_id: str, request: Request):
        try:
            UUID(run_id)
        except ValueError:
            return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None:
            return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        if set(body) - {"force"}: return error(422, "unknown field")
        with mutation_lock:
            try:
                name = bridge.default_run_name(run_dir)
                out = bridge.materialize_run(run_dir, targets_dir, name=name, force=bool(body.get("force", False)))
            except FileExistsError as exc:
                return error(409, str(exc))
            except Exception:
                return error(500, "materialize failed")
        return json({"ok": True, "name": name, "path": str(out)})

    @app.put("/api/runs/{run_id}/scope")
    async def replace_scope(run_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        allowed = {"expected_revision", "actor", "reason", "in_scope", "out_of_scope"}
        if set(body) - allowed: return error(422, "unknown field")
        for field in ("expected_revision", "actor", "reason"):
            if not isinstance(body.get(field), str) or not body[field].strip(): return error(422, f"{field} must be a non-empty string")
        if not isinstance(body.get("in_scope"), list) or not isinstance(body.get("out_of_scope"), list): return error(422, "scope rules must be lists")
        before = (run_dir / "scope.yaml").read_bytes()
        with mutation_lock:
            try:
                if load_state(run_dir).current_state != "initialized": return error(409, "scope changes are web-enabled only while the run is initialized")
                manifest = load_manifest(run_dir)
                replace_scope_rules_atomic(run_dir, body["expected_revision"], body["actor"], body["reason"], body["in_scope"], body["out_of_scope"], manifest.target)
                return json({"ok": True, "scope": web_view.scope_view(run_dir)})
            except FileExistsError as exc:
                return error(409, str(exc))
            except ScopeValidationError:
                if (run_dir / "scope.yaml").read_bytes() != before: (run_dir / "scope.yaml").write_bytes(before)
                return error(422, "scope replacement request is invalid")
            except Exception:
                return error(500, "scope replacement failed")

    @app.post("/api/runs/{run_id}/scope/check")
    async def scope_check(run_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        if set(body) - {"candidate"}: return error(422, "unknown field")
        if not isinstance(body.get("candidate"), str) or not body["candidate"].strip(): return error(422, "candidate must be a non-empty string")
        decision = evaluate_scope(load_scope(run_dir), body["candidate"]).to_dict()
        decision["scope_revision"] = scope_revision(run_dir)
        return json(decision)


    MAX_TEXT = {"expected_revision": 128, "expected_state": 64, "action_type": 64, "candidate": 512, "actor": 200, "reason": 2000, "conditions": 2000, "relative_artifact_path": 1024, "artifact_type": 64, "media_type": 200, "source": 500, "note": 2000, "skill": 128, "objective": 4000, "notes": 4000}

    def require_text(body, field):
        value = body.get(field)
        if not isinstance(value, str) or not value.strip():
            return None, error(422, f"{field} must be a non-empty string")
        if len(value) > MAX_TEXT.get(field, 2000):
            return None, error(422, f"{field} is too long")
        return value.strip(), None

    def registry_bytes(run_dir):
        p = run_dir / "approvals.jsonl"
        return p.read_bytes() if p.exists() else b""

    @app.post("/api/runs/{run_id}/approvals")
    async def grant_approval_route(run_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        allowed = {"expected_revision", "expected_state", "action_type", "candidate", "actor", "reason", "duration_minutes", "conditions"}
        if set(body) - allowed: return error(422, "unknown field")
        values = {}
        for field in ("expected_revision", "expected_state", "action_type", "candidate", "actor", "reason"):
            values[field], err = require_text(body, field)
            if err: return err
        if values["action_type"] not in ACTION_TYPES: return error(422, "unknown action_type")
        if values["action_type"] not in APPROVABLE: return error(422, "action_type cannot be approved")
        duration = body.get("duration_minutes")
        if isinstance(duration, bool) or not isinstance(duration, int): return error(422, "duration_minutes must be an integer")
        if duration < 1 or duration > 10080: return error(422, "duration_minutes must be between 1 and 10080")
        conditions = body.get("conditions")
        if conditions is not None:
            if not isinstance(conditions, str) or not conditions.strip(): return error(422, "conditions must be null or a non-empty string")
            if len(conditions) > MAX_TEXT["conditions"]: return error(422, "conditions is too long")
            conditions = conditions.strip()
        before = registry_bytes(run_dir)
        with mutation_lock:
            try:
                if load_state(run_dir).current_state != values["expected_state"]: return error(409, "expected state is stale")
                if approval_revision(run_dir) != values["expected_revision"]: return error(409, "approval revision is stale")
                approval = grant_approval(run_dir, values["action_type"], values["candidate"], values["actor"], values["reason"], duration_minutes=duration, conditions=conditions)
                payload = {"ok": True, "approval": next(a for a in web_view.approval_view(run_dir)["approvals"] if a["approval_id"] == approval.approval_id), "approvals": web_view.approval_view(run_dir)}
                return JSONResponse(payload, status_code=201, headers={"Location": f"/api/runs/{run_id}/approvals"})
            except ApprovalValidationError:
                if registry_bytes(run_dir) != before: (run_dir / "approvals.jsonl").write_bytes(before)
                return error(422, "approval grant request is invalid")
            except ApprovalPolicyError as exc:
                if registry_bytes(run_dir) != before: (run_dir / "approvals.jsonl").write_bytes(before)
                return error(409, str(exc))
            except Exception:
                if registry_bytes(run_dir) != before: (run_dir / "approvals.jsonl").write_bytes(before)
                return error(500, "approval grant failed")

    @app.post("/api/runs/{run_id}/approvals/{approval_id}/revoke")
    async def revoke_approval_route(run_id: str, approval_id: str, request: Request):
        try: UUID(run_id); UUID(approval_id)
        except ValueError: return error(422, "run_id and approval_id must be UUIDs")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        if set(body) - {"expected_revision", "actor", "reason"}: return error(422, "unknown field")
        expected, err = require_text(body, "expected_revision")
        if err: return err
        actor, err = require_text(body, "actor")
        if err: return err
        reason, err = require_text(body, "reason")
        if err: return err
        before = registry_bytes(run_dir)
        with mutation_lock:
            try:
                if approval_revision(run_dir) != expected: return error(409, "approval revision is stale")
                summary = list_approvals(run_dir)
                match = next((a for a in summary.approvals if a.approval_id == str(UUID(approval_id))), None)
                if match is None: return error(404, "approval not found")
                if match.status != "active": return error(409, f"approval is {match.status}")
                revoke_approval(run_dir, approval_id, actor, reason)
                return json({"ok": True, "revoked_approval_id": str(UUID(approval_id)), "approvals": web_view.approval_view(run_dir)})
            except ApprovalValidationError:
                if registry_bytes(run_dir) != before: (run_dir / "approvals.jsonl").write_bytes(before)
                return error(422, "approval revocation request is invalid")
            except ApprovalPolicyError as exc:
                if registry_bytes(run_dir) != before: (run_dir / "approvals.jsonl").write_bytes(before)
                return error(409, str(exc))
            except Exception:
                if registry_bytes(run_dir) != before: (run_dir / "approvals.jsonl").write_bytes(before)
                return error(500, "approval revocation failed")


    def evidence_bytes(run_dir):
        p = run_dir / "evidence.jsonl"
        return p.read_bytes() if p.exists() else b""

    def verification_counts(results):
        counts = {"verified": 0, "mismatch": 0, "missing": 0, "unsafe": 0, "other": 0}
        for item in results:
            status = getattr(item, "status", "other")
            counts[status if status in counts else "other"] += 1
        return counts

    def verification_payload(v):
        return {"evidence_id": v.evidence_id, "relative_artifact_path": v.path, "expected_sha256": v.expected_sha256, "actual_sha256": v.actual_sha256, "expected_size": v.expected_size, "actual_size": v.actual_size, "status": v.status, "reason": v.reason}

    @app.get("/api/runs/{run_id}/evidence/artifacts")
    def artifact_inventory(run_id: str):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        try:
            return json(list_artifact_candidates(run_dir).to_dict())
        except Exception:
            return error(500, "artifact inventory failed")

    @app.post("/api/runs/{run_id}/evidence")
    async def register_evidence_route(run_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        allowed = {"expected_revision", "expected_state", "relative_artifact_path", "actor", "artifact_type", "media_type", "source", "note"}
        if set(body) - allowed: return error(422, "unknown field")
        vals = {}
        for field in ("expected_revision", "expected_state", "relative_artifact_path", "actor", "artifact_type"):
            vals[field], err = require_text(body, field)
            if err: return err
        optional = {}
        for field in ("media_type", "source", "note"):
            value = body.get(field)
            if value is None:
                optional[field] = None
            elif not isinstance(value, str) or not value.strip():
                return error(422, f"{field} must be null or a non-empty string")
            elif len(value) > MAX_TEXT[field]:
                return error(422, f"{field} is too long")
            else:
                optional[field] = value.strip()
        try:
            normalize_evidence_path(vals["relative_artifact_path"])
        except EvidenceValidationError:
            return error(422, "relative_artifact_path is invalid")
        before = evidence_bytes(run_dir)
        with mutation_lock:
            try:
                if load_state(run_dir).current_state != vals["expected_state"]: return error(409, "expected state is stale")
                if evidence_revision(run_dir) != vals["expected_revision"]: return error(409, "evidence revision is stale")
                rec = register_evidence(run_dir, vals["relative_artifact_path"], vals["actor"], vals["artifact_type"], optional["media_type"], optional["source"], optional["note"])
                view = web_view.evidence_view(run_dir)
                projected = next(r for r in view["records"] if r["evidence_id"] == rec.evidence_id)
                return JSONResponse({"ok": True, "evidence": projected, "evidence_view": view}, status_code=201, headers={"Location": f"/api/runs/{run_id}/evidence"})
            except EvidenceRefusalError as exc:
                return error(409, str(exc))
            except EvidenceValidationError as exc:
                msg = str(exc)
                if "missing" in msg or "changed while hashing" in msg:
                    return error(409, msg)
                return error(422, msg)
            except Exception:
                if evidence_bytes(run_dir) != before and evidence_revision(run_dir) == vals.get("expected_revision"):
                    (run_dir / "evidence.jsonl").write_bytes(before)
                return error(500, "evidence registration failed")

    @app.post("/api/runs/{run_id}/evidence/verify")
    async def verify_evidence_route(run_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        if set(body) - {"evidence_id"}: return error(422, "unknown field")
        eid = body.get("evidence_id")
        if eid is not None:
            try: eid = str(UUID(eid))
            except Exception: return error(422, "evidence_id must be null or a UUID")
        with mutation_lock:
            try:
                if eid is not None and not any(r.evidence_id == eid for r in load_evidence_registry(run_dir).records):
                    return error(404, "evidence not found")
                results = verify_all_evidence(run_dir, eid)
                return json({"ok": True, "evidence_revision": evidence_revision(run_dir), "verification_scope": "one" if eid else "all", "results": [verification_payload(v) for v in results], "counts": verification_counts(results), "notice": "Point-in-time byte-integrity verification; this does not validate the truth or security significance of the evidence."})
            except EvidenceValidationError:
                return error(422, "evidence verification request is invalid")
            except Exception:
                return error(500, "evidence verification failed")

    @app.post("/api/runs/{run_id}/action/check")
    async def action_check(run_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        if set(body) - {"action_type", "candidate"}: return error(422, "unknown field")
        action_type, err = require_text(body, "action_type")
        if err: return err
        if action_type not in ACTION_TYPES: return error(422, "unknown action_type")
        candidate = body.get("candidate")
        if candidate is not None and (not isinstance(candidate, str) or not candidate.strip()): return error(422, "candidate must be null or a non-empty string")
        if candidate is None and action_type != "local_analysis": return error(422, "candidate is required")
        decision = evaluate_action(run_dir, action_type, candidate.strip() if isinstance(candidate, str) else None).to_dict()
        decision["approval_revision"] = approval_revision(run_dir)
        decision["notice"] = "Point-in-time deterministic policy decision only; no action was executed."
        return json(decision)


    def validate_uuid_text(value, field):
        try: return str(UUID(value))
        except Exception: raise ValueError(f"{field} must be a UUID")

    def contract_validation_response(kind, cid, report, run_dir):
        return json({"ok": True, "contract_type": f"skill_{kind}", "contract_id": cid, "validation_report": report.to_dict(), "validation_context": web_view.validation_context(run_dir), "notice": "Point-in-time contract validation; no skill or recommended action was executed."})

    def contract_body_expected(body):
        if set(body) - {"expected_revision"}: return None, error(422, "unknown field")
        expected, err = require_text(body, "expected_revision")
        if err: return None, err
        return expected, None

    @app.post("/api/runs/{run_id}/contracts/requests")
    async def create_contract_request(run_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        allowed={"expected_revision","expected_state","skill","actor","objective","action_type","candidate","input_evidence_ids","max_items","notes"}
        if set(body)-allowed: return error(422,"unknown field")
        vals={}
        for field in ("expected_revision","expected_state","skill","actor","objective","action_type"):
            vals[field], err = require_text(body, field)
            if err: return err
        if vals["skill"] not in list_known_skills(): return error(422,"unknown skill")
        if vals["action_type"] not in REQUEST_ACTIONS: return error(422,"unsupported request action")
        cand=body.get("candidate")
        if cand is None:
            if vals["action_type"] != "local_analysis": return error(422,"candidate is required")
        elif not isinstance(cand,str) or not cand.strip(): return error(422,"candidate must be null or a non-empty string")
        elif len(cand)>MAX_TEXT["candidate"]: return error(422,"candidate is too long")
        ids=body.get("input_evidence_ids", [])
        if not isinstance(ids,list): return error(422,"input_evidence_ids must be a list")
        try: ids=[str(UUID(x)) for x in ids]
        except Exception: return error(422,"input_evidence_ids must contain UUID strings")
        if len(set(ids))!=len(ids): return error(422,"duplicate evidence IDs")
        max_items=body.get("max_items",100)
        if isinstance(max_items,bool) or not isinstance(max_items,int) or max_items<1 or max_items>1000: return error(422,"max_items must be an integer from 1 through 1000")
        notes=body.get("notes")
        if notes is not None:
            if not isinstance(notes,str) or not notes.strip(): return error(422,"notes must be null or a non-empty string")
            if len(notes)>MAX_TEXT["notes"]: return error(422,"notes is too long")
            notes=notes.strip()
        with mutation_lock:
            try:
                if load_state(run_dir).current_state != vals["expected_state"]: return error(409,"expected state is stale")
                if contract_revision(run_dir) != vals["expected_revision"]: return error(409,"contract revision is stale")
                req, path, rep = create_skill_request(run_dir, vals["skill"], vals["actor"], vals["objective"], vals["action_type"], cand.strip() if isinstance(cand,str) else None, ids, max_items, notes)
                refreshed=web_view.contract_view(run_dir)
                projected=next(r for r in refreshed["requests"] if r["request_id"]==req.request_id)
                return JSONResponse({"ok":True,"request":projected,"validation_report":rep.to_dict(),"contracts":refreshed}, status_code=201, headers={"Location":f"/api/runs/{run_id}/contracts"})
            except SkillContractValidationError as exc:
                msg=str(exc)
                if "unknown evidence_id" in msg: return error(422,msg)
                if "current policy" in msg or "does not allow" in msg or "verification" in msg: return error(409,msg)
                return error(422,msg)
            except Exception:
                return error(500,"contract request creation failed")

    @app.post("/api/runs/{run_id}/contracts/requests/{request_id}/validate")
    async def validate_contract_request(run_id: str, request_id: str, request: Request):
        try: UUID(run_id); rid=str(UUID(request_id))
        except ValueError: return error(422,"run_id and request_id must be UUIDs")
        require_mutation_guard(request)
        run_dir=web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404,"run not found")
        body, err=await read_json_object(request)
        if err: return err
        expected, err=contract_body_expected(body)
        if err: return err
        with mutation_lock:
            if contract_revision(run_dir) != expected: return error(409,"contract revision is stale")
            lookup=find_skill_request_by_id(run_dir,rid)
            if lookup.status=="not_found": return error(404,"request not found")
            if lookup.status=="ambiguous": return error(409,"request ID is ambiguous")
            rep=validate_skill_request(run_dir, lookup.relative_path)
            return contract_validation_response("request", rid, rep, run_dir)

    @app.post("/api/runs/{run_id}/contracts/results/{result_id}/validate")
    async def validate_contract_result(run_id: str, result_id: str, request: Request):
        try: UUID(run_id); rid=str(UUID(result_id))
        except ValueError: return error(422,"run_id and result_id must be UUIDs")
        require_mutation_guard(request)
        run_dir=web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404,"run not found")
        body, err=await read_json_object(request)
        if err: return err
        expected, err=contract_body_expected(body)
        if err: return err
        with mutation_lock:
            if contract_revision(run_dir) != expected: return error(409,"contract revision is stale")
            lookup=find_skill_result_by_id(run_dir,rid)
            if lookup.status=="not_found": return error(404,"result not found")
            if lookup.status=="ambiguous": return error(409,"result ID is ambiguous")
            rep=validate_skill_result(run_dir, lookup.relative_path)
            return contract_validation_response("result", rid, rep, run_dir)


    @app.get("/api/runs/{run_id}/guide")
    def guide(run_id: str):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        try:
            return json(build_workflow_guide(run_dir, enrichment_enabled=mcp_enrichment_enabled))
        except Exception:
            return error(500, "guide unavailable")

    @app.post("/api/runs/{run_id}/guide/actions/{action_id}")
    async def guide_action(run_id: str, action_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        if action_id not in GUIDE_ACTION_TARGETS: return error(422, "unknown guided action")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        allowed = {"expected_state", "expected_guide_revision", "actor", "reason", "confirmed"}
        if set(body) - allowed: return error(422, "unknown field")
        if body.get("confirmed") is not True: return error(422, "confirmation must be exactly true")
        for field in ("expected_state", "expected_guide_revision", "actor"):
            if not isinstance(body.get(field), str) or not body[field].strip(): return error(422, f"{field} must be a non-empty string")
        if len(body["expected_guide_revision"]) != 64 or any(c not in "0123456789abcdef" for c in body["expected_guide_revision"]): return error(422, "expected_guide_revision must be a lowercase sha256")
        reason = body.get("reason")
        if reason is not None and (not isinstance(reason, str) or not reason.strip() or len(reason) > 2000): return error(422, "reason must be null or a non-empty bounded string")
        with mutation_lock:
            try:
                guide_now = build_workflow_guide(run_dir, enrichment_enabled=mcp_enrichment_enabled)
                if guide_now["current_state"] != body["expected_state"] or guide_now["guide_revision"] != body["expected_guide_revision"]:
                    return error(409, "This engagement changed since you opened it. Reload the latest information before continuing.")
                next_id = guide_now["next_action"]["id"]
                allowed_now = (next_id == action_id and guide_now["next_action"].get("kind") == "transition") or (action_id == "confirm_scope" and next_id == "review_scope")
                if not allowed_now or not guide_now["next_action"].get("available"):
                    return error(409, "This step is no longer available. Reload the engagement to see the current recommended action.")
                target = GUIDE_ACTION_TARGETS[action_id]
                transition_state(run_dir, target, body["actor"].strip(), reason.strip() if isinstance(reason, str) else None)
                updated = build_workflow_guide(run_dir, enrichment_enabled=mcp_enrichment_enabled)
                return json({"ok": True, "state": web_view.state_view(run_dir), "guide": updated})
            except StateValidationError as exc:
                msg = "Scope must be valid before it can be confirmed." if action_id == "confirm_scope" else "guided action rejected"
                return error(409, msg)
            except InvalidTransitionError:
                return error(409, "This step is no longer available. Reload the engagement to see the current recommended action.")
            except Exception:
                return error(500, "guided action failed")

    @app.get("/api/runs")
    def runs():
        try:
            return json(web_view.list_runs(root))
        except Exception as exc:
            return json({"runs": [], "total": 0, "errors": [{"section": "runs", "message": web_view._clean(exc)}]})

    def detail(run_id: str, name: str):
        try:
            UUID(run_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="run_id must be a UUID")
        payload = web_view.view_for_run_id(root, run_id, name)
        if payload is None:
            raise HTTPException(status_code=404, detail="run not found")
        return json(payload)

    @app.post("/api/runs/{run_id}/state/transition")
    async def state_transition(run_id: str, request: Request):
        try:
            UUID(run_id)
        except ValueError:
            return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None:
            return error(404, "run not found")
        if "application/json" not in request.headers.get("content-type", ""):
            return error(422, "JSON body required")
        try:
            body = await request.json()
        except Exception:
            return error(422, "malformed JSON")
        if not isinstance(body, dict):
            return error(422, "JSON object required")
        allowed = {"expected_state", "new_state", "actor", "reason"}
        if set(body) - allowed:
            return error(422, "unknown field")
        for field in ("expected_state", "new_state", "actor"):
            if not isinstance(body.get(field), str) or not body[field].strip():
                return error(422, f"{field} must be a non-empty string")
        reason = body.get("reason")
        if reason is not None and (not isinstance(reason, str) or not reason.strip()):
            return error(422, "reason must be null or a non-empty string")
        with mutation_lock:
            try:
                current = load_state(run_dir)
                if current.current_state != body["expected_state"]:
                    return error(409, "expected state is stale")
                transition_state(run_dir, body["new_state"], body["actor"], reason)
                return json({"ok": True, "state": web_view.state_view(run_dir)})
            except (InvalidTransitionError, StateValidationError):
                return error(409, "state transition rejected")
            except Exception:
                return error(500, "state transition failed")


    @app.get("/api/runs/{run_id}/findings/candidates")
    def finding_candidates(run_id: str):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        try: return json(web_view.finding_candidate_view(run_dir))
        except Exception: return error(500, "candidate inventory failed")

    def _hex(v, field):
        import re
        if not isinstance(v,str) or not re.fullmatch(r"[0-9a-f]{64}", v): raise ValueError(f"{field} must be a lowercase SHA-256")
        return v
    def _text(body, field, maxlen, nullable=False):
        v=body.get(field)
        if v is None and nullable: return None
        if not isinstance(v,str) or isinstance(v,bool) or not v.strip() or len(v)>maxlen: raise ValueError(f"{field} must be a non-empty string")
        return v

    @app.post("/api/runs/{run_id}/findings")
    async def promote_finding_api(run_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        allowed={"expected_finding_revision","expected_contract_revision","expected_scope_revision","expected_evidence_revision","expected_state","result_id","claim_id","expected_source_sha256","actor","title","candidate","severity","confidence","validation_basis","validation_reason","impact","remediation","location","notes","supplementary_evidence_ids"}
        if set(body)-allowed: return error(422,"unknown field")
        try:
            for f in ("expected_finding_revision","expected_contract_revision","expected_scope_revision","expected_evidence_revision","expected_source_sha256"): _hex(body.get(f), f)
            expected_state=_text(body,"expected_state",64)
            rid=str(UUID(body.get("result_id"))); cid=str(UUID(body.get("claim_id")))
            if body.get("severity") not in SEVERITIES: return error(422,"unsupported severity")
            if body.get("confidence") not in PROMOTED_CONFIDENCES: return error(422,"unsupported promoted confidence")
            if body.get("validation_basis") not in VALIDATION_BASES: return error(422,"unsupported validation_basis")
            supp=body.get("supplementary_evidence_ids",[])
            if not isinstance(supp,list): return error(422,"supplementary_evidence_ids must be an array")
            supp=[str(UUID(x)) for x in supp]
            if len(set(supp)) != len(supp): return error(422,"duplicate supplementary evidence IDs")
            args={"actor":_text(body,"actor",200),"title":_text(body,"title",500),"candidate":_text(body,"candidate",512),"severity":body["severity"],"confidence":body["confidence"],"validation_basis":body["validation_basis"],"validation_reason":_text(body,"validation_reason",4000),"impact":_text(body,"impact",8000),"remediation":_text(body,"remediation",8000),"location":_text(body,"location",2000,True),"notes":_text(body,"notes",4000,True),"supplementary_evidence_ids":supp,"expected_source_sha256":body["expected_source_sha256"]}
        except Exception:
            return error(422,"promotion request is invalid")
        with mutation_lock:
            try:
                ctx=web_view.validation_context(run_dir)
                if finding_revision(run_dir)!=body["expected_finding_revision"] or ctx["contract_revision"]!=body["expected_contract_revision"] or ctx["scope_revision"]!=body["expected_scope_revision"] or ctx["evidence_revision"]!=body["expected_evidence_revision"]: return error(409,"stale review revision")
                if load_state(run_dir).current_state != expected_state: return error(409,"expected state is stale")
                rec=promote_finding_by_ids(run_dir,rid,cid,**args)
                view=web_view.finding_view(run_dir)
                projected=next(f for f in view["findings"] if f["finding_id"]==rec.finding_id)
                return JSONResponse({"ok":True,"finding":projected,"findings":view}, status_code=201, headers={"Location":f"/api/runs/{run_id}/findings"})
            except FindingValidationError as exc: return error(422, str(exc))
            except FindingPromotionRefusal as exc:
                msg=str(exc)
                if "unknown source result" in msg or "not found" in msg: return error(404,msg)
                return error(409,msg)
            except Exception: return error(500,"finding promotion failed")

    @app.post("/api/runs/{run_id}/findings/verify")
    async def verify_findings_api(run_id: str, request: Request):
        try: UUID(run_id)
        except ValueError: return error(422, "run_id must be a UUID")
        require_mutation_guard(request)
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return error(404, "run not found")
        body, err = await read_json_object(request)
        if err: return err
        if set(body)-{"finding_id"}: return error(422,"unknown field")
        fid=body.get("finding_id")
        if fid is not None:
            try: fid=str(UUID(fid))
            except Exception: return error(422,"finding_id must be a UUID")
        with mutation_lock:
            results=verify_all_findings(run_dir,fid)
            if fid is not None and len(results)==1 and results[0].overall_status=="invalid" and results[0].reason=="finding_id is not registered": return error(404,"finding not found")
            counts={}
            for r in results: counts[r.overall_status]=counts.get(r.overall_status,0)+1
            return json({"finding_revision":finding_revision(run_dir),"verification_scope":"one" if fid else "all","results":[r.to_dict() for r in results],"counts":counts,"validation_context":{**web_view.validation_context(run_dir),"finding_revision":finding_revision(run_dir)},"notice":"Point-in-time verification only; status is not persisted and current-scope status does not by itself change overall integrity."})



    def _run_or_error(run_id: str):
        try: UUID(run_id)
        except ValueError: return None, error(422, "run_id must be a UUID")
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None: return None, error(404, "run not found")
        return run_dir, None

    @app.get("/api/runs/{run_id}/mcp")
    def mcp_catalog_route(run_id: str):
        run_dir, err = _run_or_error(run_id)
        if err: return err
        return json({"enabled": mcp_enrichment_enabled, "current_state": load_state(run_dir).current_state, "scope_revision": scope_revision(run_dir), "approval_revision": approval_revision(run_dir), "tools": mcp_catalog(mcp_enrichment_enabled), "limitations": ["One synchronous invocation at a time", "Transient result only", "No automatic artifact or evidence creation"]})

    @app.post("/api/runs/{run_id}/mcp/preflight")
    async def mcp_preflight_route(run_id: str, request: Request):
        require_mutation_guard(request)
        run_dir, err = _run_or_error(run_id)
        if err: return err
        body, err = await read_json_object(request)
        if err: return err
        if set(body) - {"tool_name", "arguments"}: return error(422, "unknown field")
        tool = body.get("tool_name")
        if not isinstance(tool, str) or not tool.strip() or len(tool) > 64: return error(422, "tool_name must be a non-empty string")
        try:
            return json(await mcp_preflight(str(run_dir), tool.strip(), body.get("arguments")))
        except InputError as exc:
            return error(422, str(exc))
        except Exception:
            return error(500, "preflight failed")

    @app.post("/api/runs/{run_id}/mcp/invoke")
    async def mcp_invoke_route(run_id: str, request: Request):
        require_mutation_guard(request)
        if not mcp_enrichment_enabled: return error(503, "MCP enrichment is disabled")
        if "application/json" not in request.headers.get("content-type", ""): return error(422, "JSON body required")
        run_dir, err = _run_or_error(run_id)
        if err: return err
        body, err = await read_json_object(request)
        if err: return err
        allowed = {"expected_state", "expected_scope_revision", "expected_approval_revision", "tool_name", "arguments", "actor", "purpose", "confirmed"}
        if set(body) - allowed: return error(422, "unknown field")
        for field, limit in (("expected_state",64),("expected_scope_revision",128),("expected_approval_revision",128),("tool_name",64),("actor",200),("purpose",2000)):
            if not isinstance(body.get(field), str) or not body[field].strip() or len(body[field]) > limit: return error(422, f"{field} must be a non-empty string")
        if body.get("confirmed") is not True: return error(422, "confirmed must be true")
        if not isinstance(body.get("arguments"), dict): return error(422, "arguments must be a JSON object")
        if not enrichment_lock.acquire(blocking=False): return error(409, "another enrichment invocation is already active")
        started = datetime.now(timezone.utc)
        invocation_id = str(__import__('uuid').uuid4())
        try:
            with mutation_lock:
                if load_state(run_dir).current_state != body["expected_state"].strip(): return error(409, "expected state is stale")
                if scope_revision(run_dir) != body["expected_scope_revision"].strip(): return error(409, "scope revision is stale")
                if approval_revision(run_dir) != body["expected_approval_revision"].strip(): return error(409, "approval revision is stale")
                tool = body["tool_name"].strip()
                args = body["arguments"]
                logger.info("mcp_enrichment_start invocation_id=%s run_id=%s tool=%s actor=%s", invocation_id, run_id, tool, body["actor"].strip())
                policy, result = await mcp_invoke(str(run_dir), tool, args, enrichment_executor or FixedEnrichmentExecutor(), web=True)
                if policy.decision != "allow": return error(409, policy.reason)
            completed = datetime.now(timezone.utc)
            duration = int((completed-started).total_seconds()*1000)
            logger.info("mcp_enrichment_finish invocation_id=%s run_id=%s tool=%s candidate=%s actor=%s status=ok duration_ms=%s result_count=%s truncated=%s", invocation_id, run_id, tool, policy.normalized_policy_candidate, body["actor"].strip(), duration, result.metadata.get("item_count"), result.metadata.get("truncated"))
            return json({"ok": True, "invocation": {"invocation_id": invocation_id, "tool_name": tool, "actor": body["actor"].strip(), "purpose": body["purpose"].strip(), "started_at": started.isoformat(), "completed_at": completed.isoformat(), "duration_ms": duration, "transient": True}, "policy": policy.to_dict(), "result": result.result, "result_metadata": result.metadata, "scope_note": _SCOPE_NOTE, "notice": _NOTICE})
        except InputError as exc:
            return error(422, str(exc))
        except EnrichmentError as exc:
            return error(exc.status_code, exc.message)
        except Exception:
            return error(500, "enrichment invocation failed")
        finally:
            enrichment_lock.release()

    @app.get("/api/runs/{run_id}/overview")
    def overview(run_id: str): return detail(run_id, "overview")
    @app.get("/api/runs/{run_id}/scope")
    def scope(run_id: str): return detail(run_id, "scope")
    @app.get("/api/runs/{run_id}/state")
    def state(run_id: str): return detail(run_id, "state")
    @app.get("/api/runs/{run_id}/evidence")
    def evidence(run_id: str): return detail(run_id, "evidence")
    @app.get("/api/runs/{run_id}/approvals")
    def approvals(run_id: str): return detail(run_id, "approvals")
    @app.get("/api/runs/{run_id}/contracts")
    def contracts(run_id: str): return detail(run_id, "contracts")
    @app.get("/api/runs/{run_id}/findings")
    def findings(run_id: str): return detail(run_id, "findings")
    @app.get("/api/runs/{run_id}/integrity")
    def integrity(run_id: str): return detail(run_id, "integrity")

    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    def index():
        return FileResponse(static_dir / "index.html")

    return app
