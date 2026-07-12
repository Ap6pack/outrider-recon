from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from uuid import UUID, uuid4

from outrider.scope import ScopeValidationError, load_scope

SCHEMA_VERSION = 1
ENGAGEMENT_TYPE = "authorized_external_recon"
INITIAL_STATE = "initialized"
STATES = frozenset({
    "initialized", "scoped", "collecting", "analyzing", "reporting",
    "completed", "cancelled", "archived",
})
ALLOWED_TRANSITIONS = {
    "initialized": {"scoped", "cancelled"},
    "scoped": {"collecting", "cancelled"},
    "collecting": {"analyzing", "cancelled"},
    "analyzing": {"collecting", "reporting", "cancelled"},
    "reporting": {"analyzing", "completed", "cancelled"},
    "completed": {"archived"},
    "cancelled": {"archived"},
    "archived": set(),
}
REASON_REQUIRED = {("analyzing", "collecting"), ("reporting", "analyzing")}


class StateValidationError(ValueError):
    pass


class InvalidTransitionError(ValueError):
    pass


@dataclass(frozen=True)
class RunManifest:
    schema_version: int
    run_id: str
    target: str
    engagement_type: str
    created_at: str
    created_by: str | None
    authorization_reference: str | None
    scope_file: str
    event_log: str
    initial_state: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RunEvent:
    schema_version: int
    sequence: int
    event_id: str
    run_id: str
    event_type: str
    occurred_at: str
    actor: str | None
    previous_state: str | None
    new_state: str
    reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RunStateSummary:
    run_id: str
    target: str
    current_state: str
    event_count: int
    created_at: str
    last_transition_at: str | None
    last_actor: str | None
    legacy_events_detected: bool
    legacy_event_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _require_nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StateValidationError(f"{field} must be a non-empty string")
    return value


def _optional_nonempty(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _require_nonempty(value, field)


def _validate_timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise StateValidationError(f"{field} must be a string timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StateValidationError(f"{field} must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StateValidationError(f"{field} must be timezone-aware")
    return value


def _validate_uuid(value: Any, field: str, version: int | None = None) -> str:
    if not isinstance(value, str):
        raise StateValidationError(f"{field} must be a UUID string")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise StateValidationError(f"{field} must be a valid UUID") from exc
    if version is not None and parsed.version != version:
        raise StateValidationError(f"{field} must be a UUID version {version}")
    return value


def _relative_filename(value: Any, field: str) -> str:
    text = _require_nonempty(value, field)
    path = Path(text)
    if path.is_absolute() or len(path.parts) != 1 or text in {".", ".."} or ".." in path.parts:
        raise StateValidationError(f"{field} must be a relative filename")
    return text


def create_manifest(target: str, actor: str | None = None, authorization_reference: str | None = None) -> RunManifest:
    return RunManifest(
        schema_version=SCHEMA_VERSION,
        run_id=str(uuid4()),
        target=_require_nonempty(target, "target"),
        engagement_type=ENGAGEMENT_TYPE,
        created_at=utc_now(),
        created_by=_optional_nonempty(actor, "created_by"),
        authorization_reference=_optional_nonempty(authorization_reference, "authorization_reference"),
        scope_file="scope.yaml",
        event_log="run.jsonl",
        initial_state=INITIAL_STATE,
    )


def validate_manifest_dict(data: Any) -> RunManifest:
    if not isinstance(data, dict):
        raise StateValidationError("manifest.json must contain a JSON object")
    required = ["schema_version", "run_id", "target", "engagement_type", "created_at", "created_by", "authorization_reference", "scope_file", "event_log", "initial_state"]
    for key in required:
        if key not in data:
            raise StateValidationError(f"manifest.json missing required field: {key}")
    if not isinstance(data["schema_version"], int):
        raise StateValidationError("schema_version must be an integer")
    if data["schema_version"] != SCHEMA_VERSION:
        raise StateValidationError("unsupported manifest schema_version")
    run_id = _validate_uuid(data["run_id"], "run_id")
    target = _require_nonempty(data["target"], "target")
    if data["engagement_type"] != ENGAGEMENT_TYPE:
        raise StateValidationError("engagement_type must be authorized_external_recon")
    created_at = _validate_timestamp(data["created_at"], "created_at")
    created_by = _optional_nonempty(data["created_by"], "created_by")
    auth_ref = _optional_nonempty(data["authorization_reference"], "authorization_reference")
    scope_file = _relative_filename(data["scope_file"], "scope_file")
    event_log = _relative_filename(data["event_log"], "event_log")
    if data["initial_state"] != INITIAL_STATE:
        raise StateValidationError("initial_state must be initialized")
    return RunManifest(data["schema_version"], run_id, target, data["engagement_type"], created_at, created_by, auth_ref, scope_file, event_log, data["initial_state"])


def load_manifest(run_dir: str | Path) -> RunManifest:
    path = Path(run_dir) / "manifest.json"
    if not path.exists():
        raise StateValidationError(f"manifest.json not found: {path}")
    try:
        return validate_manifest_dict(json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        raise StateValidationError(f"malformed JSON in manifest.json: {exc}") from exc


def write_manifest_atomic(run_dir: str | Path, manifest: RunManifest) -> None:
    path = Path(run_dir) / "manifest.json"
    if path.exists():
        raise StateValidationError("manifest.json already exists")
    fd, tmp = tempfile.mkstemp(prefix=".manifest.", suffix=".tmp", dir=Path(run_dir))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(manifest.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def make_event(manifest: RunManifest, event_type: str, sequence: int, actor: str | None, previous_state: str | None, new_state: str, reason: str | None = None) -> RunEvent:
    return RunEvent(SCHEMA_VERSION, sequence, str(uuid4()), manifest.run_id, event_type, utc_now(), actor, previous_state, new_state, reason)


def append_event(run_dir: str | Path, manifest: RunManifest, event: RunEvent) -> None:
    path = Path(run_dir) / manifest.event_log
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        handle.flush(); os.fsync(handle.fileno())


def _parse_event(data: Any, manifest: RunManifest, expected_sequence: int, current: str | None, seen: set[str]) -> RunEvent:
    if not isinstance(data, dict):
        raise StateValidationError("state event must be a JSON object")
    for key in ["schema_version", "sequence", "event_id", "run_id", "event_type", "occurred_at", "actor", "previous_state", "new_state", "reason"]:
        if key not in data:
            raise StateValidationError(f"state event missing required field: {key}")
    if data["schema_version"] != SCHEMA_VERSION:
        raise StateValidationError("unsupported event schema_version")
    if data["sequence"] != expected_sequence:
        raise StateValidationError("state event sequence must increment by exactly one")
    event_id = _validate_uuid(data["event_id"], "event_id")
    if event_id in seen:
        raise StateValidationError("duplicate event_id in state log")
    seen.add(event_id)
    if data["run_id"] != manifest.run_id:
        raise StateValidationError("event run_id does not match manifest")
    _validate_timestamp(data["occurred_at"], "occurred_at")
    event_type = data["event_type"]
    if event_type not in {"run_initialized", "state_transition"}:
        raise StateValidationError("unknown state event_type")
    actor = _optional_nonempty(data["actor"], "actor")
    prev = data["previous_state"]
    if prev is not None and prev not in STATES:
        raise StateValidationError("previous_state is not recognized")
    new = data["new_state"]
    if new not in STATES:
        raise StateValidationError("new_state is not recognized")
    reason = _optional_nonempty(data["reason"], "reason")
    if event_type == "run_initialized":
        if data["sequence"] != 1 or prev is not None or new != manifest.initial_state:
            raise StateValidationError("invalid run_initialized event")
    else:
        if actor is None:
            raise StateValidationError("actor is required for state transitions")
        if prev != current:
            raise StateValidationError("previous_state does not match derived current state")
        _validate_transition(prev, new, reason)
    return RunEvent(data["schema_version"], data["sequence"], event_id, data["run_id"], event_type, data["occurred_at"], actor, prev, new, reason)


def _validate_transition(previous: str | None, new: str, reason: str | None) -> None:
    if previous is None:
        raise InvalidTransitionError("state transitions require a previous state")
    if new == previous:
        raise InvalidTransitionError("cannot transition to the current state")
    if previous == "archived":
        raise InvalidTransitionError("archived is terminal")
    if new not in ALLOWED_TRANSITIONS[previous]:
        raise InvalidTransitionError(f"transition {previous} -> {new} is not allowed")
    if new == "cancelled" and not reason:
        raise InvalidTransitionError("transition to cancelled requires a reason")
    if (previous, new) in REASON_REQUIRED and not reason:
        raise InvalidTransitionError(f"transition {previous} -> {new} requires a reason")


def load_state(run_dir: str | Path) -> RunStateSummary:
    manifest = load_manifest(run_dir)
    path = Path(run_dir) / manifest.event_log
    if not path.exists():
        raise StateValidationError(f"event log not found: {path}")
    current: str | None = None
    count = 0; legacy = 0; seen: set[str] = set(); last_at = None; last_actor = None; started = False
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if raw == "":
            if started:
                raise StateValidationError(f"blank line in versioned event log at line {lineno}")
            legacy += 1; continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            if started:
                raise StateValidationError(f"malformed JSON in event log at line {lineno}: {exc}") from exc
            raise StateValidationError(f"malformed JSON in event log at line {lineno}: {exc}") from exc
        if isinstance(data, dict) and "schema_version" in data:
            started = True
            event = _parse_event(data, manifest, count + 1, current, seen)
            count += 1; current = event.new_state; last_at = event.occurred_at; last_actor = event.actor or last_actor
        elif started:
            raise StateValidationError(f"unversioned event after versioned state stream at line {lineno}")
        else:
            legacy += 1
    if count == 0:
        raise StateValidationError("no schema-versioned state events found")
    return RunStateSummary(manifest.run_id, manifest.target, current or manifest.initial_state, count, manifest.created_at, last_at, last_actor, legacy > 0, legacy)


def transition_state(run_dir: str | Path, new_state: str, actor: str, reason: str | None = None) -> RunStateSummary:
    actor = _require_nonempty(actor, "actor")
    if new_state not in STATES:
        raise InvalidTransitionError("new_state is not recognized")
    manifest = load_manifest(run_dir)
    summary = load_state(run_dir)
    _validate_transition(summary.current_state, new_state, reason)
    if summary.current_state == "initialized" and new_state == "scoped":
        try:
            load_scope(run_dir)
        except ScopeValidationError as exc:
            raise StateValidationError(str(exc)) from exc
    event = make_event(manifest, "state_transition", summary.event_count + 1, actor, summary.current_state, new_state, reason)
    append_event(run_dir, manifest, event)
    return load_state(run_dir)


def initialize_state(run_dir: str | Path, target: str, actor: str | None = None, authorization_reference: str | None = None) -> RunManifest:
    run_dir = Path(run_dir)
    manifest = create_manifest(target, actor, authorization_reference)
    write_manifest_atomic(run_dir, manifest)
    event = make_event(manifest, "run_initialized", 1, actor, None, INITIAL_STATE, None)
    append_event(run_dir, manifest, event)
    return manifest


def bootstrap_legacy_run(run_dir: str | Path, target: str, actor: str, authorization_reference: str | None = None) -> RunStateSummary:
    run_dir = Path(run_dir)
    if not run_dir.exists():
        raise StateValidationError(f"run folder not found: {run_dir}")
    _require_nonempty(actor, "actor"); _require_nonempty(target, "target")
    if (run_dir / "manifest.json").exists():
        raise InvalidTransitionError("state tracking already exists")
    load_scope(run_dir)
    if not (run_dir / "run.jsonl").exists():
        raise StateValidationError("run.jsonl not found")
    manifest = create_manifest(target, actor, authorization_reference)
    write_manifest_atomic(run_dir, manifest)
    event = make_event(manifest, "run_initialized", 1, actor, None, INITIAL_STATE, "legacy bootstrap")
    append_event(run_dir, manifest, event)
    return load_state(run_dir)
