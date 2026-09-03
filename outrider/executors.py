"""Skill executors for the governed orchestrator loop.

An executor is the boundary that turns a ``skill_request`` into a
``skill_result`` written under ``contracts/results/``. The orchestrator itself
never runs a skill or touches the network; it delegates to an injected executor.
This mirrors the injected-executor pattern already used at the MCP boundary
(``outrider.mcp_enrichment.FixedEnrichmentExecutor`` and the test/web
``FakeExecutor``), which keeps the loop deterministic and offline in CI.

Two executors are provided:

``StubExecutor``
    Replays scripted results from fixtures. No model, no network. Used by the
    benchmark harness and the unit tests.

``ClaudeSubprocessExecutor``
    Runs a real agent out of process, one hop per request. Offline/live only,
    disabled by default, and gated behind explicit operator intent (ADR 0017
    and the Anthropic Cyber Verification note in the docs).
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from outrider.skill_contract import (
    RESULT_CONTRACT_TYPE,
    SkillContractValidationError,
    SkillRequest,
    load_skill_result,
    utc_now,
)
from outrider.state import load_manifest


class ExecutorError(RuntimeError):
    """Raised when an executor cannot produce a result for a request."""


@runtime_checkable
class Executor(Protocol):
    """Turns a validated ``SkillRequest`` into a ``skill_result`` file.

    Implementations MUST write exactly one ``contracts/results/<uuid>.json``
    file for the given request and return its path. They MUST set
    ``request_id`` to ``request.request_id``, ``run_id`` to the run manifest's
    id, and ``skill`` to ``request.skill`` so that
    ``skill_contract.validate_skill_result`` can link the result to its request.
    """

    def run(self, run_dir: str | Path, request: SkillRequest) -> Path: ...


def _write_result_atomic(run_dir: Path, payload: dict[str, Any]) -> Path:
    out = run_dir / "contracts" / "results" / f"{payload['result_id']}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise ExecutorError("result file already exists")
    fd, tmp = tempfile.mkstemp(prefix=f".{payload['result_id']}.", suffix=".tmp", dir=out.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return out


def build_result_payload(
    run_dir: str | Path,
    request: SkillRequest,
    *,
    status: str,
    summary: str,
    claims: list[dict[str, Any]] | None = None,
    discovered_candidates: list[dict[str, Any]] | None = None,
    recommended_actions: list[dict[str, Any]] | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble a schema-shaped ``skill_result`` dict linked to ``request``.

    Fresh UUIDs are minted for ``result_id`` and each claim's ``claim_id`` when
    absent, so replayed scripts do not need to carry ids. Content fields (claim
    subjects/statements, discovered candidates) are taken verbatim from the
    caller, which is what the deterministic benchmark judge scores against.
    """
    manifest = load_manifest(run_dir)
    out_claims: list[dict[str, Any]] = []
    for claim in claims or []:
        entry = dict(claim)
        entry.setdefault("claim_id", str(uuid4()))
        entry.setdefault("suggested_severity", None)
        out_claims.append(entry)
    return {
        "schema_version": 1,
        "contract_type": RESULT_CONTRACT_TYPE,
        "result_id": str(uuid4()),
        "request_id": request.request_id,
        "run_id": manifest.run_id,
        "skill": request.skill,
        "completed_at": utc_now(),
        "status": status,
        "summary": summary,
        "claims": out_claims,
        "discovered_candidates": list(discovered_candidates or []),
        "recommended_actions": list(recommended_actions or []),
        "errors": list(errors or []),
    }


@dataclass(frozen=True)
class ResultScript:
    """A canned result a ``StubExecutor`` returns for a matched request.

    ``claims``, ``discovered_candidates``, ``recommended_actions`` and
    ``errors`` are lists of contract-shaped dicts. Any evidence IDs they cite
    must already be registered and verified in the run, exactly as a real skill
    would be required to do (see ``skill_contract._verify_evidence_ids``).
    """

    status: str = "completed"
    summary: str = "stub result"
    claims: list[dict[str, Any]] = field(default_factory=list)
    discovered_candidates: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)


class StubExecutor:
    """Deterministic executor that replays scripted results.

    Scripts are keyed by the request's candidate (the normalized
    ``requested_action.candidate``), falling back to the sentinel ``"*"`` for a
    default script and finally to a minimal ``blocked`` result when nothing
    matches. No network or model is involved, so a corpus run is reproducible.
    """

    NO_MATCH = "no scripted result for this request"

    def __init__(self, scripts: dict[str, ResultScript] | None = None, *, default: ResultScript | None = None):
        self._scripts = dict(scripts or {})
        if default is not None:
            self._scripts.setdefault("*", default)

    def script_for(self, request: SkillRequest) -> ResultScript | None:
        candidate = request.requested_action.get("candidate")
        if candidate is not None and candidate in self._scripts:
            return self._scripts[candidate]
        return self._scripts.get("*")

    def run(self, run_dir: str | Path, request: SkillRequest) -> Path:
        run = Path(run_dir)
        script = self.script_for(request)
        if script is None:
            payload = build_result_payload(
                run,
                request,
                status="blocked",
                summary=self.NO_MATCH,
                errors=[{"code": "no_script", "message": self.NO_MATCH}],
            )
            return _write_result_atomic(run, payload)
        payload = build_result_payload(
            run,
            request,
            status=script.status,
            summary=script.summary,
            claims=script.claims,
            discovered_candidates=script.discovered_candidates,
            recommended_actions=script.recommended_actions,
            errors=script.errors,
        )
        return _write_result_atomic(run, payload)


class ClaudeSubprocessExecutor:
    """Run a real agent out of process, one hop per request (offline/live only).

    This executor is intentionally not used by CI or the benchmark harness. It
    shells out to the ``claude`` CLI with the skills directory added, hands it
    the request contract path, and expects the agent to write a
    ``skill_result`` under ``contracts/results/`` per ``run-contract.md``. It is
    disabled unless explicitly constructed with ``enabled=True`` because
    autonomous execution depends on an external agent runtime and its provider
    safeguards (Anthropic Cyber Verification enrollment; see the docs).
    """

    def __init__(
        self,
        *,
        enabled: bool = False,
        skills_dir: str | Path = Path.home() / ".claude" / "skills",
        model: str = "opus",
        command: str = "claude",
        timeout_seconds: int = 900,
    ):
        self.enabled = enabled
        self.skills_dir = Path(skills_dir)
        self.model = model
        self.command = command
        self.timeout_seconds = timeout_seconds

    def run(self, run_dir: str | Path, request: SkillRequest) -> Path:
        if not self.enabled:
            raise ExecutorError(
                "ClaudeSubprocessExecutor is disabled by default; live autonomous "
                "execution requires explicit opt-in and provider safeguard enrollment"
            )
        run = Path(run_dir)
        request_path = run / "contracts" / "requests" / f"{request.request_id}.json"
        prompt = (
            "Operate under skills/_shared/run-contract.md for run_dir "
            f"{run}. Execute the skill_request at {request_path} and write a "
            "schema-valid skill_result v1 under contracts/results/. Emit only "
            "observation, exposure, hypothesis, or finding_candidate claims."
        )
        before = self._result_ids(run)
        argv = [
            self.command,
            "--model", self.model,
            "--add-dir", str(self.skills_dir),
            "-p", prompt,
        ]
        try:
            subprocess.run(argv, cwd=str(run), timeout=self.timeout_seconds, check=True, capture_output=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ExecutorError(f"agent execution failed: {exc}") from exc
        after = self._result_ids(run)
        created = sorted(after - before)
        if not created:
            raise ExecutorError("agent produced no new skill_result")
        path = run / "contracts" / "results" / created[-1]
        try:
            result = load_skill_result(run, path)
        except SkillContractValidationError as exc:
            raise ExecutorError(f"agent produced an invalid skill_result: {exc}") from exc
        if result.request_id != request.request_id:
            raise ExecutorError("agent result does not link to the dispatched request")
        return path

    @staticmethod
    def _result_ids(run: Path) -> set[str]:
        base = run / "contracts" / "results"
        if not base.is_dir():
            return set()
        return {p.name for p in base.iterdir() if p.suffix == ".json" and p.is_file()}
