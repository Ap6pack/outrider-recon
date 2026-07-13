from __future__ import annotations

from pathlib import Path
from uuid import UUID

from outrider import web_view


def create_app(runs_root: str | Path):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import FileResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError('Install web dependencies with: python -m pip install -e ".[web]"') from exc

    root = Path(runs_root)
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

    def json(payload):
        return JSONResponse(payload)

    @app.get("/api/health")
    def health():
        return {"ok": True, "service": "outrider-web", "mode": "read-only", "network_scope": "loopback-only"}

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
