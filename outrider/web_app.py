from __future__ import annotations

import secrets
import threading
from pathlib import Path
from uuid import UUID

from outrider import web_view
from outrider.state import InvalidTransitionError, StateValidationError, load_state, transition_state

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
        return {"ok": True, "service": "outrider-web", "mode": "limited-control", "network_scope": "loopback-only", "authentication": "none", "state_transition": True}

    @app.get("/api/session")
    def session():
        return json({"mode": "limited-control", "authentication": "none", "control_token": token, "capabilities": {"state_transition": True, "run_creation": False, "scope_edit": False, "approval_mutation": False, "evidence_registration": False, "contract_mutation": False, "finding_promotion": False, "mcp_invocation": False, "recon_execution": False}})

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
        run_dir = web_view._run_dir_for_id(root, run_id)
        if run_dir is None:
            return error(404, "run not found")
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
