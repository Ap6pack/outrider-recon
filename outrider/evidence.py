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

from outrider.state import RunManifest, StateValidationError, load_manifest, load_state

SCHEMA_VERSION = 1
EVENT_TYPE = "evidence_registered"
REGISTRY_FILE = "evidence.jsonl"
ARTIFACTS_DIR = "artifacts"
ARTIFACT_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHUNK_SIZE = 1024 * 1024


class EvidenceValidationError(ValueError):
    pass


class EvidenceRegistrationError(ValueError):
    pass


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


def ensure_evidence_storage(run_dir: str | Path) -> None:
    run_path = Path(run_dir)
    (run_path / ARTIFACTS_DIR).mkdir(exist_ok=True)
    registry = run_path / REGISTRY_FILE
    if not registry.exists():
        registry.touch()


def _nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceValidationError(f"{field} must be a non-empty string")
    return value


def _optional_nonempty(value: Any, field: str) -> str | None:
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


def normalize_evidence_path(relative_path: str) -> str:
    if not isinstance(relative_path, str) or not relative_path:
        raise EvidenceValidationError("path must be a non-empty relative path")
    text = relative_path.replace("\\", "/")
    pure = PurePosixPath(text)
    if pure.is_absolute() or text in {".", ".."} or any(part in {"", ".", ".."} for part in pure.parts):
        raise EvidenceValidationError("path must be a canonical relative POSIX path without traversal")
    if not pure.parts or pure.parts[0] != ARTIFACTS_DIR or len(pure.parts) == 1:
        raise EvidenceValidationError("evidence path must be beneath artifacts/")
    return pure.as_posix()


def _validate_artifact_path(run_dir: Path, relative_path: str) -> tuple[str, Path]:
    normalized = normalize_evidence_path(relative_path)
    run_real = run_dir.resolve(strict=True)
    artifact = run_dir / normalized
    try:
        resolved = artifact.resolve(strict=False)
        resolved.relative_to(run_real)
    except ValueError as exc:
        raise EvidenceValidationError("evidence path escapes the run folder") from exc
    parent = run_dir
    for part in PurePosixPath(normalized).parts[:-1]:
        parent = parent / part
        try:
            st = parent.lstat()
        except FileNotFoundError as exc:
            raise EvidenceValidationError("artifact parent directory does not exist") from exc
        if stat.S_ISLNK(st.st_mode):
            raise EvidenceValidationError("artifact parent directories must not be symlinks")
        if not stat.S_ISDIR(st.st_mode):
            raise EvidenceValidationError("artifact parent path must be a directory")
    try:
        st = artifact.lstat()
    except FileNotFoundError as exc:
        raise EvidenceValidationError("artifact file not found") from exc
    if stat.S_ISLNK(st.st_mode):
        raise EvidenceValidationError("artifact must not be a symlink")
    if stat.S_ISDIR(st.st_mode):
        raise EvidenceValidationError("artifact path is a directory")
    if not stat.S_ISREG(st.st_mode):
        raise EvidenceValidationError("artifact must be a regular file")
    return normalized, artifact


def _hash_regular_file(path: Path) -> tuple[str, int]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise EvidenceValidationError("artifact must remain a regular file")
    digest = hashlib.sha256(); size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk); digest.update(chunk)
    after = path.lstat()
    if not stat.S_ISREG(after.st_mode) or stat.S_ISLNK(after.st_mode):
        raise EvidenceValidationError("artifact changed type while being hashed")
    before_tuple = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    after_tuple = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if before_tuple != after_tuple or size != after.st_size:
        raise EvidenceValidationError("artifact changed while being hashed")
    return digest.hexdigest(), size


def _parse_record(data: Any, manifest: RunManifest, expected_sequence: int, seen_ids: set[str], seen_paths: set[str]) -> EvidenceRecord:
    if not isinstance(data, dict):
        raise EvidenceValidationError("evidence record must be a JSON object")
    required = ["schema_version", "sequence", "event_type", "evidence_id", "run_id", "registered_at", "actor", "path", "artifact_type", "sha256", "size_bytes", "media_type", "source", "note"]
    for key in required:
        if key not in data:
            raise EvidenceValidationError(f"evidence record missing required field: {key}")
    if data["schema_version"] != SCHEMA_VERSION:
        raise EvidenceValidationError("unsupported evidence schema_version")
    if not isinstance(data["sequence"], int) or data["sequence"] != expected_sequence:
        raise EvidenceValidationError("evidence sequence must increment by exactly one")
    if data["event_type"] != EVENT_TYPE:
        raise EvidenceValidationError("unknown evidence event_type")
    evidence_id = _uuid4(data["evidence_id"])
    if evidence_id in seen_ids:
        raise EvidenceValidationError("duplicate evidence_id in registry")
    seen_ids.add(evidence_id)
    if data["run_id"] != manifest.run_id:
        raise EvidenceValidationError("evidence run_id does not match manifest")
    registered_at = _timestamp(data["registered_at"])
    actor = _nonempty(data["actor"], "actor")
    path = normalize_evidence_path(data["path"])
    if path in seen_paths:
        raise EvidenceValidationError("duplicate evidence path in registry")
    seen_paths.add(path)
    artifact_type = _nonempty(data["artifact_type"], "artifact_type")
    if not ARTIFACT_TYPE_RE.fullmatch(artifact_type):
        raise EvidenceValidationError("artifact_type must match [a-z][a-z0-9_-]{0,63}")
    sha256 = data["sha256"]
    if not isinstance(sha256, str) or not SHA256_RE.fullmatch(sha256):
        raise EvidenceValidationError("sha256 must be 64 lowercase hexadecimal characters")
    size_bytes = data["size_bytes"]
    if not isinstance(size_bytes, int) or size_bytes < 0:
        raise EvidenceValidationError("size_bytes must be a non-negative integer")
    media_type = _optional_nonempty(data["media_type"], "media_type")
    source = _optional_nonempty(data["source"], "source")
    note = _optional_nonempty(data["note"], "note")
    return EvidenceRecord(SCHEMA_VERSION, data["sequence"], EVENT_TYPE, evidence_id, manifest.run_id, registered_at, actor, path, artifact_type, sha256, size_bytes, media_type, source, note)


def load_evidence_registry(run_dir: str | Path) -> EvidenceRegistrySummary:
    manifest = load_manifest(run_dir)
    try:
        load_state(run_dir)
    except StateValidationError as exc:
        raise EvidenceValidationError(str(exc)) from exc
    path = Path(run_dir) / REGISTRY_FILE
    if not path.exists():
        return EvidenceRegistrySummary(manifest.run_id, 0, ())
    records: list[EvidenceRecord] = []; seen_ids: set[str] = set(); seen_paths: set[str] = set(); started = False
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if raw == "":
            if started:
                raise EvidenceValidationError(f"blank line in evidence registry at line {lineno}")
            continue
        started = True
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EvidenceValidationError(f"malformed JSON in evidence registry at line {lineno}: {exc}") from exc
        records.append(_parse_record(data, manifest, len(records) + 1, seen_ids, seen_paths))
    return EvidenceRegistrySummary(manifest.run_id, len(records), tuple(records))


def register_evidence(run_dir: str | Path, relative_path: str, actor: str, artifact_type: str, media_type: str | None = None, source: str | None = None, note: str | None = None) -> EvidenceRecord:
    run_path = Path(run_dir)
    manifest = load_manifest(run_path)
    try:
        state = load_state(run_path)
    except StateValidationError as exc:
        raise EvidenceValidationError(str(exc)) from exc
    if state.current_state == "archived":
        raise EvidenceRegistrationError("archived runs do not accept new evidence")
    summary = load_evidence_registry(run_path)
    actor = _nonempty(actor, "actor")
    if not ARTIFACT_TYPE_RE.fullmatch(_nonempty(artifact_type, "artifact_type")):
        raise EvidenceValidationError("artifact_type must match [a-z][a-z0-9_-]{0,63}")
    media_type = _optional_nonempty(media_type, "media_type")
    source = _optional_nonempty(source, "source")
    note = _optional_nonempty(note, "note")
    normalized, artifact = _validate_artifact_path(run_path, relative_path)
    if any(record.path == normalized for record in summary.records):
        raise EvidenceRegistrationError("evidence path is already registered")
    sha256, size = _hash_regular_file(artifact)
    record = EvidenceRecord(SCHEMA_VERSION, summary.evidence_count + 1, EVENT_TYPE, str(uuid4()), manifest.run_id, utc_now(), actor, normalized, artifact_type, sha256, size, media_type, source, note)
    ensure_evidence_storage(run_path)
    with (run_path / REGISTRY_FILE).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
        handle.flush(); os.fsync(handle.fileno())
    return record


def verify_evidence(run_dir: str | Path, evidence_id: str) -> EvidenceVerification:
    summary = load_evidence_registry(run_dir)
    for record in summary.records:
        if record.evidence_id == evidence_id:
            return _verify_record(Path(run_dir), record)
    return EvidenceVerification(evidence_id, "", "", None, 0, None, "missing", "evidence ID not found")


def verify_all_evidence(run_dir: str | Path) -> tuple[EvidenceVerification, ...]:
    summary = load_evidence_registry(run_dir)
    return tuple(_verify_record(Path(run_dir), record) for record in summary.records)


def _verify_record(run_dir: Path, record: EvidenceRecord) -> EvidenceVerification:
    try:
        _, artifact = _validate_artifact_path(run_dir, record.path)
        actual_sha, actual_size = _hash_regular_file(artifact)
    except EvidenceValidationError as exc:
        reason = str(exc)
        status = "missing" if "not found" in reason or "does not exist" in reason else "unsafe"
        return EvidenceVerification(record.evidence_id, record.path, record.sha256, None, record.size_bytes, None, status, reason)
    if actual_sha == record.sha256 and actual_size == record.size_bytes:
        return EvidenceVerification(record.evidence_id, record.path, record.sha256, actual_sha, record.size_bytes, actual_size, "verified", "artifact matches registered hash and size")
    return EvidenceVerification(record.evidence_id, record.path, record.sha256, actual_sha, record.size_bytes, actual_size, "mismatch", "artifact hash or size differs from registry")
