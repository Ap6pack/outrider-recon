from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any
from uuid import UUID, uuid4

from outrider.state import StateValidationError, load_manifest, load_state

SCHEMA_VERSION = 1
EVENT_TYPE = "evidence_registered"
REGISTRY = "evidence.jsonl"
ARTIFACTS = "artifacts"
_ARTIFACT_TYPE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CHUNK = 1024 * 1024

class EvidenceValidationError(ValueError):
    pass

class EvidenceRegistrationError(ValueError):
    pass

class EvidenceRefusalError(EvidenceRegistrationError):
    pass


@dataclass(frozen=True)
class ArtifactCandidate:
    relative_artifact_path: str
    size_bytes: int
    registered: bool
    evidence_id: str | None
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(frozen=True)
class ArtifactInventory:
    candidates: tuple[ArtifactCandidate, ...]
    truncated: bool
    counts: dict[str, int]
    max_files: int
    max_depth: int
    notice: str
    def to_dict(self) -> dict[str, Any]:
        return {"candidates": [c.to_dict() for c in self.candidates], "truncated": self.truncated, "counts": self.counts, "max_files": self.max_files, "max_depth": self.max_depth, "notice": self.notice}

@dataclass(frozen=True)
class EvidenceRecord:
    schema_version: int
    sequence: int
    event_type: str
    evidence_id: str
    run_id: str
    registered_at: str
    actor: str
    path: str
    artifact_type: str
    sha256: str
    size_bytes: int
    media_type: str | None
    source: str | None
    note: str | None
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(frozen=True)
class EvidenceRegistrySummary:
    run_id: str
    evidence_count: int
    records: tuple[EvidenceRecord, ...]
    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "evidence_count": self.evidence_count, "records": [r.to_dict() for r in self.records]}

@dataclass(frozen=True)
class EvidenceVerification:
    evidence_id: str
    path: str
    expected_sha256: str
    actual_sha256: str | None
    expected_size: int
    actual_size: int | None
    status: str
    reason: str
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def _nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceValidationError(f"{field} must be a non-empty string")
    return value

def _optional(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _nonempty(value, field)

def _timestamp(value: Any) -> str:
    if not isinstance(value, str):
        raise EvidenceValidationError("registered_at must be a string timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceValidationError("registered_at must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceValidationError("registered_at must be timezone-aware")
    return value

def _uuid4(value: Any) -> str:
    if not isinstance(value, str):
        raise EvidenceValidationError("evidence_id must be a UUID string")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise EvidenceValidationError("evidence_id must be a valid UUID") from exc
    if parsed.version != 4:
        raise EvidenceValidationError("evidence_id must be a UUID version 4")
    return value

def normalize_evidence_path(path_value: str) -> str:
    text = _nonempty(path_value, "path").replace("\\", "/")
    p = PurePosixPath(text)
    if p.is_absolute() or text in {"", ".", ".."} or any(part in {"", ".", ".."} for part in p.parts):
        raise EvidenceValidationError("path must be a canonical relative POSIX path")
    if not p.parts or p.parts[0] != ARTIFACTS or len(p.parts) == 1:
        raise EvidenceValidationError("evidence path must be beneath artifacts/")
    return p.as_posix()

def _validate_artifact_type(value: Any) -> str:
    text = _nonempty(value, "artifact_type")
    if not _ARTIFACT_TYPE.fullmatch(text):
        raise EvidenceValidationError("artifact_type must match [a-z][a-z0-9_-]{0,63}")
    return text

def _parse_record(data: Any, manifest_run_id: str, expected_sequence: int, ids: set[str], paths: set[str]) -> EvidenceRecord:
    if not isinstance(data, dict):
        raise EvidenceValidationError("evidence record must be a JSON object")
    required = ["schema_version","sequence","event_type","evidence_id","run_id","registered_at","actor","path","artifact_type","sha256","size_bytes","media_type","source","note"]
    for key in required:
        if key not in data:
            raise EvidenceValidationError(f"evidence record missing required field: {key}")
    if data["schema_version"] != SCHEMA_VERSION:
        raise EvidenceValidationError("unsupported evidence schema_version")
    if data["sequence"] != expected_sequence:
        raise EvidenceValidationError("evidence sequence must increment by exactly one")
    if data["event_type"] != EVENT_TYPE:
        raise EvidenceValidationError("unknown evidence event_type")
    evidence_id = _uuid4(data["evidence_id"])
    if evidence_id in ids:
        raise EvidenceValidationError("duplicate evidence_id in registry")
    ids.add(evidence_id)
    if data["run_id"] != manifest_run_id:
        raise EvidenceValidationError("evidence run_id does not match manifest")
    registered_at = _timestamp(data["registered_at"])
    actor = _nonempty(data["actor"], "actor")
    path = normalize_evidence_path(data["path"])
    if path in paths:
        raise EvidenceValidationError("duplicate evidence path in registry")
    paths.add(path)
    artifact_type = _validate_artifact_type(data["artifact_type"])
    sha256 = data["sha256"]
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise EvidenceValidationError("sha256 must contain 64 lowercase hexadecimal characters")
    size = data["size_bytes"]
    if not isinstance(size, int) or size < 0:
        raise EvidenceValidationError("size_bytes must be a non-negative integer")
    return EvidenceRecord(SCHEMA_VERSION, data["sequence"], EVENT_TYPE, evidence_id, data["run_id"], registered_at, actor, path, artifact_type, sha256, size, _optional(data["media_type"], "media_type"), _optional(data["source"], "source"), _optional(data["note"], "note"))

def load_evidence_registry(run_dir: str | Path) -> EvidenceRegistrySummary:
    manifest = load_manifest(run_dir)
    path = Path(run_dir) / REGISTRY
    if not path.exists():
        return EvidenceRegistrySummary(manifest.run_id, 0, ())
    records=[]; ids=set(); paths=set(); seen_record=False
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if raw == "":
            if seen_record:
                raise EvidenceValidationError(f"blank line in evidence registry at line {lineno}")
            continue
        seen_record=True
        try:
            data=json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EvidenceValidationError(f"malformed JSON in evidence registry at line {lineno}: {exc}") from exc
        records.append(_parse_record(data, manifest.run_id, len(records)+1, ids, paths))
    return EvidenceRegistrySummary(manifest.run_id, len(records), tuple(records))


def evidence_revision(run_dir: str | Path) -> str:
    """Return SHA-256 of exact evidence.jsonl bytes as a stale-write token, not a signature.

    Missing legacy registries are equivalent to empty bytes. The registry is not
    created or modified, mtimes are ignored, and artifact changes do not affect
    this optimistic revision.
    """
    path = Path(run_dir) / REGISTRY
    data = path.read_bytes() if path.exists() else b""
    return hashlib.sha256(data).hexdigest()

def list_artifact_candidates(run_dir: str | Path, *, max_files: int = 1000, max_depth: int = 16) -> ArtifactInventory:
    """Return bounded metadata-only regular-file candidates beneath artifacts/.

    Inventory never follows symlinks, opens file contents, hashes artifacts, or
    exposes absolute paths. Direct filesystem races may affect this point-in-time
    listing; registration remains authoritative.
    """
    if max_files < 1 or max_depth < 0:
        raise EvidenceValidationError("inventory limits must be positive")
    run = Path(run_dir)
    root = run / ARTIFACTS
    candidates: list[ArtifactCandidate] = []
    skipped = 0
    truncated = False
    registered = {r.path: r.evidence_id for r in load_evidence_registry(run).records}
    def visit(path: Path, rel_parts: tuple[str, ...], depth: int) -> None:
        nonlocal skipped, truncated
        if truncated:
            return
        try:
            st = os.lstat(path)
        except OSError:
            skipped += 1; return
        if stat.S_ISLNK(st.st_mode):
            skipped += 1; return
        if stat.S_ISDIR(st.st_mode):
            if depth >= max_depth:
                skipped += 1; return
            try:
                children = sorted(path.iterdir(), key=lambda p: p.name)
            except OSError:
                skipped += 1; return
            for child in children:
                visit(child, rel_parts + (child.name,), depth + 1)
                if truncated: return
            return
        if not stat.S_ISREG(st.st_mode):
            skipped += 1; return
        rel = PurePosixPath(ARTIFACTS, *rel_parts).as_posix()
        try:
            rel = normalize_evidence_path(rel)
        except EvidenceValidationError:
            skipped += 1; return
        if len(candidates) >= max_files:
            truncated = True; return
        eid = registered.get(rel)
        candidates.append(ArtifactCandidate(rel, int(st.st_size), eid is not None, eid))
    if not root.exists():
        skipped = 0
    else:
        visit(root, tuple(), 0)
    candidates.sort(key=lambda c: c.relative_artifact_path)
    reg_count = sum(1 for c in candidates if c.registered)
    counts = {"eligible_files": len(candidates), "registered_files": reg_count, "unregistered_files": len(candidates)-reg_count, "unsafe_or_skipped_entries": skipped}
    return ArtifactInventory(tuple(candidates), truncated, counts, max_files, max_depth, "Metadata-only point-in-time inventory; external filesystem races are possible and registration revalidates paths and bytes.")

def validate_artifact_path(run_dir: str | Path, relative_path: str) -> tuple[str, Path]:
    run = Path(run_dir).resolve()
    normalized = normalize_evidence_path(relative_path)
    full = run / normalized
    artifacts = run / ARTIFACTS
    # reject symlink parent components without following final path
    current = run
    for part in PurePosixPath(normalized).parts[:-1]:
        current = current / part
        try: st = os.lstat(current)
        except OSError as exc: raise EvidenceValidationError(f"artifact parent path is missing: {part}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise EvidenceValidationError("evidence path contains a symbolic-link parent component")
        if not stat.S_ISDIR(st.st_mode):
            raise EvidenceValidationError("evidence path parent is not a directory")
    try:
        real_parent = full.parent.resolve(strict=True)
    except OSError as exc:
        raise EvidenceValidationError("artifact parent path is missing") from exc
    if os.path.commonpath([str(run), str(real_parent)]) != str(run) or os.path.commonpath([str(artifacts), str(real_parent)]) != str(artifacts):
        raise EvidenceValidationError("evidence path escapes artifacts/")
    try:
        st = os.lstat(full)
    except FileNotFoundError as exc:
        raise EvidenceValidationError("evidence artifact is missing") from exc
    if stat.S_ISLNK(st.st_mode):
        raise EvidenceValidationError("evidence artifact must not be a symbolic link")
    if stat.S_ISDIR(st.st_mode):
        raise EvidenceValidationError("evidence artifact must not be a directory")
    if not stat.S_ISREG(st.st_mode):
        raise EvidenceValidationError("evidence artifact must be a regular file")
    return normalized, full

def _hash_regular_file(path: Path) -> tuple[str, int]:
    try:
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode): raise EvidenceValidationError("evidence artifact must be a regular file")
        h=hashlib.sha256(); size=0
        with path.open("rb") as handle:
            while True:
                chunk=handle.read(_CHUNK)
                if not chunk: break
                h.update(chunk); size += len(chunk)
        after = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise EvidenceValidationError(f"could not hash evidence artifact: {exc}") from exc
    if not stat.S_ISREG(after.st_mode) or (before.st_ino,before.st_dev,before.st_mtime_ns,before.st_size)!=(after.st_ino,after.st_dev,after.st_mtime_ns,after.st_size):
        raise EvidenceValidationError("evidence artifact changed while hashing")
    if size != after.st_size:
        raise EvidenceValidationError("evidence artifact size changed while hashing")
    return h.hexdigest(), size

def register_evidence(run_dir: str | Path, relative_path: str, actor: str, artifact_type: str, media_type: str | None=None, source: str | None=None, note: str | None=None) -> EvidenceRecord:
    run_dir=Path(run_dir)
    manifest=load_manifest(run_dir)
    summary=load_state(run_dir)
    if summary.current_state == "archived":
        raise EvidenceRefusalError("archived runs do not accept new evidence")
    registry=load_evidence_registry(run_dir)
    normalized, artifact_path = validate_artifact_path(run_dir, relative_path)
    if any(r.path == normalized for r in registry.records):
        raise EvidenceRefusalError("evidence path is already registered")
    actor=_nonempty(actor,"actor"); artifact_type=_validate_artifact_type(artifact_type)
    media_type=_optional(media_type,"media_type"); source=_optional(source,"source"); note=_optional(note,"note")
    sha, size = _hash_regular_file(artifact_path)
    record=EvidenceRecord(SCHEMA_VERSION, registry.evidence_count+1, EVENT_TYPE, str(uuid4()), manifest.run_id, utc_now(), actor, normalized, artifact_type, sha, size, media_type, source, note)
    path=run_dir/REGISTRY
    path.touch(exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record.to_dict(), sort_keys=True)+"\n")
        handle.flush(); os.fsync(handle.fileno())
    return record

def verify_evidence(run_dir: str | Path, record: EvidenceRecord) -> EvidenceVerification:
    try:
        normalized, path = validate_artifact_path(run_dir, record.path)
        sha, size = _hash_regular_file(path)
    except EvidenceValidationError as exc:
        reason=str(exc)
        status="missing" if "missing" in reason else "unsafe"
        return EvidenceVerification(record.evidence_id, record.path, record.sha256, None, record.size_bytes, None, status, reason)
    if sha != record.sha256 or size != record.size_bytes:
        return EvidenceVerification(record.evidence_id, normalized, record.sha256, sha, record.size_bytes, size, "mismatch", "sha256 or size_bytes does not match registry")
    return EvidenceVerification(record.evidence_id, normalized, record.sha256, sha, record.size_bytes, size, "verified", "artifact matches registry")

def verify_all_evidence(run_dir: str | Path, evidence_id: str | None=None) -> list[EvidenceVerification]:
    load_state(run_dir)  # validate durable state stream
    registry=load_evidence_registry(run_dir)
    records=list(registry.records)
    if evidence_id is not None:
        records=[r for r in records if r.evidence_id == evidence_id]
        if not records:
            return [EvidenceVerification(evidence_id, "", "", None, 0, None, "missing", "evidence_id is not registered")]
    return [verify_evidence(run_dir, r) for r in records]
