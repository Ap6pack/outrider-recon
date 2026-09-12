"""Safe, conservative repair of a governed run folder (ADR 0022).

An unattended run can be interrupted by a crash mid-append, leaving a strict
JSONL ledger with a truncated trailing line — which then breaks the whole run,
because :func:`outrider.state.load_state` and
:func:`outrider.evidence.load_evidence_registry` reject any malformed line. This
module diagnoses such damage and repairs only what is provably safe:

* drop a **single contiguous tail** of malformed/blank lines from a JSONL ledger
  (only when every line before it parses) — backing the original bytes up to
  ``<file>.corrupt-<timestamp>`` first;
* recreate a missing static template file (the ``assets.json`` family and the
  markdown views), a missing empty ledger, or a missing standard directory.

It NEVER fabricates evidence, approval, or finding records, never edits a line in
the middle of a ledger, and refuses (reporting the issue as ``manual``) when the
manifest, state log, or scope are missing or corrupt — those carry authorization
and identity and must be inspected by a human. It does not touch the
orchestrator's ``contracts/inflight`` markers, which are a crash-recovery signal,
not corruption.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from outrider.run_setup import (
    DEFAULT_FILES,
    render_findings_md,
    render_report_md,
    render_surface_md,
    render_technique_cards_md,
)
from outrider.state import StateValidationError, load_manifest

# JSONL ledgers that may be safely tail-truncated. run.jsonl (the state log) is
# deliberately excluded: dropping a state event changes the run's current state,
# so a damaged state log is always escalated to a human.
_TAIL_REPAIRABLE_LEDGERS = ("evidence.jsonl", "approvals.jsonl", "findings.jsonl")
_RECREATABLE_LEDGERS = ("evidence.jsonl", "approvals.jsonl", "findings.jsonl")
_STANDARD_DIRS = ("artifacts", "contracts/requests", "contracts/results")


def _is_json(line: str) -> bool:
    try:
        json.loads(line)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _jsonl_tail_status(raw: str) -> tuple[str, list[str]]:
    """Classify a JSONL body as ``ok``, ``safe_repair`` (a contiguous bad tail),
    or ``manual`` (a bad line with a valid line after it). Returns the good prefix
    lines so a safe repair can rewrite the file from them."""
    segs = raw.split("\n")
    if segs and segs[-1] == "":  # a normal trailing newline
        segs = segs[:-1]
    good: list[str] = []
    bad_start: int | None = None
    for i, s in enumerate(segs):
        if s == "" or not _is_json(s):
            bad_start = i
            break
        good.append(s)
    if bad_start is None:
        return "ok", good
    for s in segs[bad_start:]:
        if s != "" and _is_json(s):
            return "manual", good  # a valid line follows a bad one -> mid-file damage
    return "safe_repair", good


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".repair-tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _default_json_text(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _scan(run: Path) -> list[dict[str, Any]]:
    """Read-only issue scan. Each issue is {kind, target, severity, detail} where
    severity is ``safe_repair`` or ``manual``."""
    issues: list[dict[str, Any]] = []

    # Manifest and scope carry identity/authorization: missing or corrupt is manual.
    try:
        manifest = load_manifest(run)
    except StateValidationError as exc:
        issues.append({"kind": "manifest_unreadable", "target": "manifest.json", "severity": "manual", "detail": str(exc)})
        return issues
    if not (run / "scope.yaml").is_file():
        issues.append({"kind": "missing_scope", "target": "scope.yaml", "severity": "manual", "detail": "scope defines authorization and cannot be regenerated safely"})
    if not (run / "run.jsonl").is_file():
        issues.append({"kind": "missing_state_log", "target": "run.jsonl", "severity": "manual", "detail": "the state log carries the run's current state and cannot be fabricated"})

    # JSONL ledgers: tail truncation is safe; mid-file damage is manual.
    for name in ("run.jsonl",) + _TAIL_REPAIRABLE_LEDGERS:
        p = run / name
        if not p.is_file():
            if name in _RECREATABLE_LEDGERS:
                issues.append({"kind": "missing_ledger", "target": name, "severity": "safe_repair", "detail": "recreate as empty (initial state)"})
            continue
        status, _good = _jsonl_tail_status(p.read_text(encoding="utf-8"))
        if status == "ok":
            continue
        if name == "run.jsonl":
            issues.append({"kind": "damaged_state_log", "target": name, "severity": "manual", "detail": f"state log has a {status} JSONL problem; inspect by hand"})
        elif status == "safe_repair":
            issues.append({"kind": "trailing_malformed_line", "target": name, "severity": "safe_repair", "detail": "drop the contiguous malformed/blank tail (a crash mid-append)"})
        else:
            issues.append({"kind": "malformed_line_midfile", "target": name, "severity": "manual", "detail": "a valid line follows a malformed one; possible data loss, inspect by hand"})

    # Missing static template files are safe to recreate (no engagement data).
    for name in DEFAULT_FILES:
        if not (run / name).is_file():
            issues.append({"kind": "missing_default_file", "target": name, "severity": "safe_repair", "detail": "recreate from the static template"})
    for name in ("findings.md", "technique_cards.md", "surface.md", "report.md"):
        if not (run / name).is_file():
            issues.append({"kind": "missing_markdown", "target": name, "severity": "safe_repair", "detail": "recreate the working-view markdown"})
    for rel in _STANDARD_DIRS:
        if not (run / rel).is_dir():
            issues.append({"kind": "missing_dir", "target": rel, "severity": "safe_repair", "detail": "recreate the standard directory"})

    return issues


def diagnose_run(run_dir: str | Path) -> dict[str, Any]:
    """Read-only diagnosis. Returns issues split into safe-to-repair and manual."""
    run = Path(run_dir)
    issues = _scan(run)
    safe = [i for i in issues if i["severity"] == "safe_repair"]
    manual = [i for i in issues if i["severity"] == "manual"]
    return {"run_dir": str(run), "ok": not issues, "issues": issues, "safe_repairable": safe, "manual": manual}


def repair_run(run_dir: str | Path, *, apply: bool = False) -> dict[str, Any]:
    """Diagnose and, when ``apply`` is set, perform only the safe repairs.

    Returns the diagnosis plus a ``repaired`` list of what changed. Manual issues
    are never touched. A manifest that cannot be read stops the repair."""
    run = Path(run_dir)
    result: dict[str, Any] = {**diagnose_run(run), "applied": bool(apply), "repaired": []}
    if not apply:
        return result
    if any(i["kind"] == "manifest_unreadable" for i in result["issues"]):
        return result  # cannot safely repair without a readable manifest

    repaired: list[dict[str, Any]] = []
    target = None
    try:
        target = load_manifest(run).target
    except StateValidationError:
        target = "target"

    for issue in result["safe_repairable"]:
        kind, name = issue["kind"], issue["target"]
        if kind == "trailing_malformed_line":
            p = run / name
            raw = p.read_text(encoding="utf-8")
            status, good = _jsonl_tail_status(raw)
            if status != "safe_repair":
                continue  # changed since scan; skip defensively
            backup = run / f"{name}.corrupt-{_now_stamp()}"
            backup.write_text(raw, encoding="utf-8")
            _write_atomic(p, ("\n".join(good) + "\n") if good else "")
            repaired.append({"kind": kind, "target": name, "backup": backup.name})
        elif kind in ("missing_ledger",):
            (run / name).write_text("", encoding="utf-8")
            repaired.append({"kind": kind, "target": name})
        elif kind == "missing_default_file":
            _write_atomic(run / name, _default_json_text(DEFAULT_FILES[name]))
            repaired.append({"kind": kind, "target": name})
        elif kind == "missing_markdown":
            renderer = {
                "findings.md": render_findings_md,
                "technique_cards.md": render_technique_cards_md,
                "surface.md": render_surface_md,
                "report.md": render_report_md,
            }[name]
            _write_atomic(run / name, renderer(target))
            repaired.append({"kind": kind, "target": name})
        elif kind == "missing_dir":
            (run / name).mkdir(parents=True, exist_ok=True)
            repaired.append({"kind": kind, "target": name})

    result["repaired"] = repaired
    # Re-scan so the caller sees what remains (should be only manual issues).
    post = diagnose_run(run)
    result["remaining"] = post["issues"]
    result["ok"] = not post["issues"]
    return result
