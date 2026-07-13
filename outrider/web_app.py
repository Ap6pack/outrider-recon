import secrets
import threading
from pathlib import Path
from uuid import UUID

from outrider import web_view
from outrider.approval import (
    ACTION_TYPES, APPROVABLE, ApprovalPolicyError, ApprovalValidationError,
    approval_revision, evaluate_action, grant_approval, list_approvals, revoke_approval,
)
from outrider.state import InvalidTransitionError, StateValidationError, load_manifest, load_state, transition_state
from outrider.scope import ScopeValidationError, evaluate_scope, load_scope, replace_scope_rules_atomic, scope_revision
from outrider.run_setup import RunConflictError, RunSetupError, WebRunRequest, create_web_run_atomic

TOKEN_HEADER = "X-Outrider-Control-Token"


def create_app(runs_root: str | Path, *, control_token: str | None = None):
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.responses import FileResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError('Install web dependencies with: python -m pip install -e ".[web]"') from exc

    root = Path(runs_root)
    token = control_token if control_token is not None else secrets.token_urlsafe(32)
    mutation_lock = threading.Lock()
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
        return {"ok": True, "service": "outrider-web", "mode": "limited-control", "network_scope": "loopback-only", "authentication": "none", "capabilities": {"state_transition": True, "run_creation": True, "scope_edit": True, "scope_check": True, "approval_mutation": True, "action_check": True, "evidence_registration": False, "contract_mutation": False, "finding_promotion": False, "mcp_invocation": False, "recon_execution": False}}

    @app.get("/api/session")
    def session():
        return json({"mode": "limited-control", "authentication": "none", "control_token": token, "capabilities": {"state_transition": True, "run_creation": True, "scope_edit": True, "scope_check": True, "approval_mutation": True, "action_check": True, "evidence_registration": False, "contract_mutation": False, "finding_promotion": False, "mcp_invocation": False, "recon_execution": False}})


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
        allowed = {"target", "actor", "authorization_reference", "in_scope", "out_of_scope"}
        if set(body) - allowed: return error(422, "unknown field")
        for field in ("target", "actor", "authorization_reference"):
            if not isinstance(body.get(field), str) or not body[field].strip():
                return error(422, f"{field} must be a non-empty string")
        if "in_scope" not in body or "out_of_scope" not in body:
            return error(422, "in_scope and out_of_scope are required")
        with mutation_lock:
            try:
                run_dir = create_web_run_atomic(root, WebRunRequest(body["target"], body["actor"], body["authorization_reference"], body["in_scope"], body["out_of_scope"]))
                manifest = load_manifest(run_dir)
                payload = {"ok": True, "run": web_view.run_overview(run_dir), "scope": web_view.scope_view(run_dir)}
                return JSONResponse(payload, status_code=201, headers={"Location": f"/api/runs/{manifest.run_id}/overview"})
            except RunConflictError:
                return error(409, "run destination already exists")
            except (RunSetupError, ScopeValidationError, ValueError):
                return error(422, "run creation request is invalid")
            except Exception:
                return error(500, "run creation failed")

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


    MAX_TEXT = {"expected_revision": 128, "expected_state": 64, "action_type": 64, "candidate": 512, "actor": 200, "reason": 2000, "conditions": 2000}

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
