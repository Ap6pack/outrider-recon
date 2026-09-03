"""Independent, advisory verifier for finding candidates (ADR 0018).

The verifier iterates the finding candidates surfaced by
:func:`outrider.finding.list_finding_candidates` and, for each, attempts to
falsify the claim against its cited evidence and current scope, emitting a
``verification`` verdict of ``supported``, ``refuted``, or
``insufficient_evidence``. Verdicts are advisory: they are written under
``contracts/verification/`` and never modify ``findings.jsonl``, never promote,
and never change ``promotion_eligible``. A human reviewer remains the decision
maker (ADR 0006). The falsification analyzer is pluggable; a deterministic
analyzer is the default and is used in tests, while an agent-backed analyzer can
run in a separate context offline.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from outrider.finding import list_finding_candidates
from outrider.skill_contract import utc_now
from outrider.state import load_manifest

VERDICTS = frozenset({"supported", "refuted", "insufficient_evidence"})
CONTRACT_TYPE = "verification"
VERIFICATION_DIR = "verification"

# An analyzer takes a finding-candidate projection dict and returns
# (verdict, rationale). It must not mutate run state.
Analyzer = Callable[[dict[str, Any]], "tuple[str, str]"]


class VerifierError(ValueError):
    pass


@dataclass(frozen=True)
class Verdict:
    schema_version: int
    contract_type: str
    verdict_id: str
    run_id: str
    result_id: str
    request_id: str
    claim_id: str
    subject: str
    verdict: str
    rationale: str
    evidence_status: str
    scope_status: str
    created_by: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _evidence_status(candidate: dict[str, Any]) -> str:
    statuses = [a.get("verification_status") for a in candidate.get("evidence_assessments", [])]
    if not statuses:
        return "no_evidence"
    if all(s == "verified" for s in statuses):
        return "verified"
    if any(s == "mismatch" for s in statuses):
        return "mismatch"
    return next((s for s in statuses if s != "verified"), "unverified")


def deterministic_falsifier(candidate: dict[str, Any]) -> tuple[str, str]:
    """Refute on tampered evidence, defer on unverified evidence or out-of-scope.

    This is the default, reproducible analyzer. It does not consult a model; it
    applies the same evidence and scope signals the promotion workflow would,
    framed as a falsification attempt.
    """
    ev = _evidence_status(candidate)
    scope_allowed = candidate.get("subject_scope_decision", {}).get("decision") == "allow"
    if ev == "mismatch":
        return "refuted", "cited evidence does not match the registry (possible tampering)"
    if ev != "verified":
        return "insufficient_evidence", f"cited evidence does not verify ({ev})"
    if not scope_allowed:
        return "insufficient_evidence", "claim subject is not currently within authorized scope"
    return "supported", "cited evidence verifies and the subject is in scope; no falsification found"


def _ensure_dir(run: Path) -> Path:
    load_manifest(run)  # refuse to operate on a non-run folder
    base = run / "contracts" / VERIFICATION_DIR
    if base.exists() and os.path.islink(base):
        raise VerifierError("contracts/verification must not be a symbolic link")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _write_verdict_atomic(base: Path, verdict: Verdict) -> Path:
    out = base / f"{verdict.verdict_id}.json"
    fd, tmp = tempfile.mkstemp(prefix=f".{verdict.verdict_id}.", suffix=".tmp", dir=base)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(verdict.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return out


def verify_candidates(
    run_dir: str | Path,
    *,
    analyzer: Analyzer | None = None,
    actor: str = "verifier",
    max_results: int = 1000,
) -> list[Verdict]:
    """Produce an advisory verdict for each finding candidate in the run.

    Verdicts are written under ``contracts/verification/``. Nothing is promoted
    and no append-only registry is touched.
    """
    run = Path(run_dir)
    base = _ensure_dir(run)
    analyze = analyzer or deterministic_falsifier
    manifest = load_manifest(run)
    projection = list_finding_candidates(run, max_results=max_results)
    verdicts: list[Verdict] = []
    for candidate in projection.get("candidates", []):
        label, rationale = analyze(candidate)
        if label not in VERDICTS:
            raise VerifierError(f"analyzer returned unsupported verdict: {label!r}")
        verdict = Verdict(
            schema_version=1,
            contract_type=CONTRACT_TYPE,
            verdict_id=str(uuid4()),
            run_id=manifest.run_id,
            result_id=candidate["result_id"],
            request_id=candidate["request_id"],
            claim_id=candidate["claim_id"],
            subject=candidate["subject"],
            verdict=label,
            rationale=rationale,
            evidence_status=_evidence_status(candidate),
            scope_status=candidate.get("subject_scope_decision", {}).get("decision", "unknown"),
            created_by=actor,
            created_at=utc_now(),
        )
        _write_verdict_atomic(base, verdict)
        verdicts.append(verdict)
    return verdicts


def list_verifications(run_dir: str | Path) -> list[dict[str, Any]]:
    """Read persisted verdicts (skips non-regular files and symlinks)."""
    run = Path(run_dir)
    base = run / "contracts" / VERIFICATION_DIR
    if not base.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for child in sorted(base.iterdir(), key=lambda p: p.name):
        try:
            st = os.lstat(child)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or child.suffix != ".json":
            continue
        try:
            data = json.loads(child.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("contract_type") == CONTRACT_TYPE:
            out.append(data)
    return out


def verification_summary(run_dir: str | Path) -> dict[str, Any]:
    """Aggregate verdict counts for a run (advisory; gates nothing)."""
    verdicts = list_verifications(run_dir)
    counts = {v: 0 for v in sorted(VERDICTS)}
    for entry in verdicts:
        label = entry.get("verdict")
        if label in counts:
            counts[label] += 1
    return {"verdict_count": len(verdicts), "counts": counts}
