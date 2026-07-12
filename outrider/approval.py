from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from outrider.scope import (
    ScopeValidationError,
    evaluate_scope_path,
    _normalize_candidate,
)
from outrider.state import StateValidationError, load_manifest, load_state

SCHEMA_VERSION = 1
REGISTRY = "approvals.jsonl"
MAX_LIFETIME = timedelta(days=7)
LOCAL = {"local_analysis"}
PASSIVE = {"public_source_lookup"}
ACTIVE = {"target_read_only_request", "target_enumeration"}
INTRUSIVE = {"intrusive_validation"}
PROHIBITED = {
    "credential_abuse",
    "destructive_validation",
    "persistence",
    "malware",
    "evasion",
    "uncontrolled_exploitation",
}
ACTION_TYPES = LOCAL | PASSIVE | ACTIVE | INTRUSIVE | PROHIBITED
APPROVABLE = ACTIVE | INTRUSIVE
ALLOWED_STATES = {
    "local_analysis": {
        "initialized",
        "scoped",
        "collecting",
        "analyzing",
        "reporting",
        "completed",
        "cancelled",
        "archived",
    },
    "public_source_lookup": {"scoped", "collecting", "analyzing", "reporting"},
    "target_read_only_request": {"scoped", "collecting", "analyzing"},
    "target_enumeration": {"scoped", "collecting", "analyzing"},
    "intrusive_validation": {"collecting", "analyzing"},
}


class ApprovalValidationError(ValueError):
    pass


class ApprovalPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ApprovalEvent:
    schema_version: int
    sequence: int
    event_id: str
    event_type: str
    approval_id: str
    run_id: str
    occurred_at: str
    actor: str
    reason: str
    action_type: str | None = None
    candidate: str | None = None
    candidate_type: str | None = None
    expires_at: str | None = None
    conditions: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.event_type == "approval_revoked":
            return {
                k: d[k]
                for k in [
                    "schema_version",
                    "sequence",
                    "event_id",
                    "event_type",
                    "approval_id",
                    "run_id",
                    "occurred_at",
                    "actor",
                    "reason",
                ]
            }
        return d


@dataclass(frozen=True)
class ApprovalGrant:
    sequence: int
    approval_id: str
    run_id: str
    occurred_at: str
    actor: str
    action_type: str
    candidate: str
    candidate_type: str
    expires_at: str
    reason: str
    conditions: str | None
    status: str
    revoked_at: str | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None
    revocation_sequence: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalRegistrySummary:
    run_id: str
    approval_count: int
    active_count: int
    expired_count: int
    revoked_count: int
    approvals: tuple[ApprovalGrant, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "approval_count": self.approval_count,
            "active_count": self.active_count,
            "expired_count": self.expired_count,
            "revoked_count": self.revoked_count,
            "approvals": [a.to_dict() for a in self.approvals],
        }


@dataclass(frozen=True)
class ActionDecision:
    action_type: str
    action_class: str | None
    decision: str
    workflow_state: str | None
    original_candidate: str | None
    normalized_candidate: str | None
    candidate_type: str | None
    scope_decision: str | None
    matched_scope_rule: str | None
    approval_required: bool
    matched_approval_id: str | None
    approval_status: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def parse_ts(v: Any, field="timestamp") -> datetime:
    if not isinstance(v, str):
        raise ApprovalValidationError(f"{field} must be a string timestamp")
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalValidationError(
            f"{field} must be a valid ISO-8601 timestamp"
        ) from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ApprovalValidationError(f"{field} must be timezone-aware")
    return dt.astimezone(timezone.utc)


def nonempty(v: Any, field: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ApprovalValidationError(f"{field} must be a non-empty string")
    return v


def uuid4str(v: Any, field: str) -> str:
    if not isinstance(v, str):
        raise ApprovalValidationError(f"{field} must be a UUID string")
    try:
        u = UUID(v)
    except ValueError as exc:
        raise ApprovalValidationError(f"{field} must be a valid UUID") from exc
    if u.version != 4:
        raise ApprovalValidationError(f"{field} must be a UUID version 4")
    return str(u)


def normalize_candidate(candidate: str) -> tuple[str, str]:
    try:
        n, t, _ = _normalize_candidate(candidate)
    except ScopeValidationError as exc:
        raise ApprovalValidationError(str(exc)) from exc
    return n, t


def action_class(a: str) -> str:
    if a in LOCAL:
        return "local"
    if a in PASSIVE:
        return "passive"
    if a in ACTIVE:
        return "active"
    if a in INTRUSIVE:
        return "intrusive"
    if a in PROHIBITED:
        return "prohibited"
    raise ApprovalValidationError("unknown action_type")


def _status(ev: ApprovalEvent, revoked: ApprovalEvent | None, now: datetime) -> str:
    if revoked:
        return "revoked"
    return "active" if now < parse_ts(ev.expires_at, "expires_at") else "expired"


def _append(path: Path, event: ApprovalEvent) -> None:
    with path.open("a", encoding="utf-8") as h:
        h.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        h.flush()
        os.fsync(h.fileno())


def _parse(
    data: Any,
    run_id: str,
    seq: int,
    event_ids: set[str],
    grant_ids: set[str],
    grants: dict[str, ApprovalEvent],
    revokes: dict[str, ApprovalEvent],
) -> ApprovalEvent:
    if not isinstance(data, dict):
        raise ApprovalValidationError("approval event must be a JSON object")
    common = {
        "schema_version",
        "sequence",
        "event_id",
        "event_type",
        "approval_id",
        "run_id",
        "occurred_at",
        "actor",
        "reason",
    }
    et = data.get("event_type")
    allowed = common | (
        {"action_type", "candidate", "candidate_type", "expires_at", "conditions"}
        if et == "approval_granted"
        else set()
    )
    for k in common:
        if k not in data:
            raise ApprovalValidationError(f"approval event missing required field: {k}")
    if set(data) - allowed:
        raise ApprovalValidationError(
            f"unknown approval event field: {sorted(set(data)-allowed)[0]}"
        )
    if (
        not isinstance(data["schema_version"], int)
        or data["schema_version"] != SCHEMA_VERSION
    ):
        raise ApprovalValidationError("unsupported approval schema_version")
    if not isinstance(data["sequence"], int) or data["sequence"] != seq:
        raise ApprovalValidationError("approval sequence must increment by exactly one")
    eid = uuid4str(data["event_id"], "event_id")
    if eid in event_ids:
        raise ApprovalValidationError("duplicate event_id in approval registry")
    event_ids.add(eid)
    aid = uuid4str(data["approval_id"], "approval_id")
    if data["run_id"] != run_id:
        raise ApprovalValidationError("approval run_id does not match manifest")
    occurred = parse_ts(data["occurred_at"], "occurred_at")
    actor = nonempty(data["actor"], "actor")
    reason = nonempty(data["reason"], "reason")
    if et == "approval_granted":
        for k in [
            "action_type",
            "candidate",
            "candidate_type",
            "expires_at",
            "conditions",
        ]:
            if k not in data:
                raise ApprovalValidationError(
                    f"approval grant missing required field: {k}"
                )
        if aid in grant_ids:
            raise ApprovalValidationError("duplicate approval_id in approval grants")
        grant_ids.add(aid)
        at = nonempty(data["action_type"], "action_type")
        if at not in ACTION_TYPES:
            raise ApprovalValidationError("unknown action_type")
        cand = nonempty(data["candidate"], "candidate")
        ctype = nonempty(data["candidate_type"], "candidate_type")
        n, nt = normalize_candidate(cand)
        if cand != n or ctype != nt:
            raise ApprovalValidationError(
                "candidate or candidate_type is not normalized"
            )
        exp = parse_ts(data["expires_at"], "expires_at")
        if exp <= occurred:
            raise ApprovalValidationError("expires_at must be later than occurred_at")
        if exp - occurred > MAX_LIFETIME:
            raise ApprovalValidationError(
                "approval lifetime must not exceed seven days"
            )
        cond = data["conditions"]
        if cond is not None:
            nonempty(cond, "conditions")
        ev = ApprovalEvent(
            SCHEMA_VERSION,
            seq,
            eid,
            et,
            aid,
            run_id,
            iso(occurred),
            actor,
            reason,
            at,
            cand,
            ctype,
            iso(exp),
            cond,
        )
        grants[aid] = ev
        return ev
    if et == "approval_revoked":
        if aid not in grants:
            raise ApprovalValidationError("revocation references no grant")
        if aid in revokes:
            raise ApprovalValidationError("duplicate revocation")
        grant = grants[aid]
        if parse_ts(grant.expires_at, "expires_at") <= occurred:
            raise ApprovalValidationError("revocation references no active grant")
        ev = ApprovalEvent(
            SCHEMA_VERSION, seq, eid, et, aid, run_id, iso(occurred), actor, reason
        )
        revokes[aid] = ev
        return ev
    raise ApprovalValidationError("unknown approval event_type")


def load_approval_registry(
    run_dir: str | Path, now: datetime | None = None
) -> ApprovalRegistrySummary:
    manifest = load_manifest(run_dir)
    path = Path(run_dir) / REGISTRY
    now = now or utc_now_dt()
    if not path.exists():
        return ApprovalRegistrySummary(manifest.run_id, 0, 0, 0, 0, ())
    grants = {}
    revokes = {}
    events = set()
    grant_ids = set()
    started = False
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if raw == "":
            if started:
                raise ApprovalValidationError(
                    f"blank line in approval registry at line {lineno}"
                )
            continue
        started = True
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ApprovalValidationError(
                f"malformed JSON in approval registry at line {lineno}: {exc}"
            ) from exc
        _parse(
            data,
            manifest.run_id,
            len(grants) + len(revokes) + 1,
            events,
            grant_ids,
            grants,
            revokes,
        )
    approvals = []
    for aid, g in sorted(grants.items(), key=lambda kv: kv[1].sequence):
        r = revokes.get(aid)
        st = _status(g, r, now)
        approvals.append(
            ApprovalGrant(
                g.sequence,
                aid,
                g.run_id,
                g.occurred_at,
                g.actor,
                g.action_type or "",
                g.candidate or "",
                g.candidate_type or "",
                g.expires_at or "",
                g.reason,
                g.conditions,
                st,
                r.occurred_at if r else None,
                r.actor if r else None,
                r.reason if r else None,
                r.sequence if r else None,
            )
        )
    return ApprovalRegistrySummary(
        manifest.run_id,
        len(approvals),
        sum(a.status == "active" for a in approvals),
        sum(a.status == "expired" for a in approvals),
        sum(a.status == "revoked" for a in approvals),
        tuple(approvals),
    )


def list_approvals(
    run_dir: str | Path, now: datetime | None = None
) -> ApprovalRegistrySummary:
    return load_approval_registry(run_dir, now)


def _ensure_registry(run_dir: str | Path) -> Path:
    p = Path(run_dir) / REGISTRY
    if not p.exists():
        p.touch()
    return p


def grant_approval(
    run_dir,
    action_type,
    candidate,
    actor,
    reason,
    *,
    duration_minutes: int | None = None,
    expires_at: str | datetime | None = None,
    conditions=None,
    now: datetime | None = None,
) -> ApprovalGrant:
    now = now or utc_now_dt()
    actor = nonempty(actor, "actor")
    reason = nonempty(reason, "reason")
    if (duration_minutes is None) == (expires_at is None):
        raise ApprovalValidationError("exactly one expiry option is required")
    cls = action_class(action_type)
    if action_type not in APPROVABLE:
        raise ApprovalPolicyError(f"{action_type} cannot be approved")
    if duration_minutes is not None:
        if not isinstance(duration_minutes, int):
            raise ApprovalValidationError("duration_minutes must be an integer")
        if duration_minutes < 1 or duration_minutes > 10080:
            raise ApprovalValidationError(
                "duration_minutes must be between 1 and 10080"
            )
        exp = now + timedelta(minutes=duration_minutes)
    else:
        exp = (
            expires_at
            if isinstance(expires_at, datetime)
            else parse_ts(expires_at, "expires_at")
        )
    if exp <= now:
        raise ApprovalValidationError("expires_at must be later than occurred_at")
    if exp - now > MAX_LIFETIME:
        raise ApprovalPolicyError("approval lifetime must not exceed seven days")
    if conditions is not None:
        conditions = nonempty(conditions, "conditions")
    manifest = load_manifest(run_dir)
    state = load_state(run_dir)
    if state.current_state not in {"scoped", "collecting", "analyzing"}:
        raise ApprovalPolicyError(
            f"approval grant is not permitted in state {state.current_state}"
        )
    n, ctype = normalize_candidate(candidate)
    sd = evaluate_scope_path(run_dir, n)
    if sd.decision == "error":
        raise ApprovalValidationError(sd.reason)
    if sd.decision != "allow":
        raise ApprovalPolicyError("candidate is outside scope")
    summary = load_approval_registry(run_dir, now)
    if any(
        a.status == "active" and a.action_type == action_type and a.candidate == n
        for a in summary.approvals
    ):
        raise ApprovalPolicyError("active duplicate approval exists")
    p = _ensure_registry(run_dir)
    ev = ApprovalEvent(
        SCHEMA_VERSION,
        summary.approval_count + summary.revoked_count + 1,
        str(uuid4()),
        "approval_granted",
        str(uuid4()),
        manifest.run_id,
        iso(now),
        actor,
        reason,
        action_type,
        n,
        ctype,
        iso(exp),
        conditions,
    )
    _append(p, ev)
    return load_approval_registry(run_dir, now).approvals[-1]


def revoke_approval(
    run_dir, approval_id, actor, reason, *, now: datetime | None = None
) -> ApprovalEvent:
    now = now or utc_now_dt()
    actor = nonempty(actor, "actor")
    reason = nonempty(reason, "reason")
    aid = uuid4str(approval_id, "approval_id")
    manifest = load_manifest(run_dir)
    load_state(run_dir)
    summary = load_approval_registry(run_dir, now)
    match = next((a for a in summary.approvals if a.approval_id == aid), None)
    if not match or match.status != "active":
        raise ApprovalPolicyError("approval is unknown or inactive")
    ev = ApprovalEvent(
        SCHEMA_VERSION,
        summary.approval_count + summary.revoked_count + 1,
        str(uuid4()),
        "approval_revoked",
        aid,
        manifest.run_id,
        iso(now),
        actor,
        reason,
    )
    _append(_ensure_registry(run_dir), ev)
    return ev


def evaluate_action(
    run_dir, action_type, candidate=None, *, now: datetime | None = None
) -> ActionDecision:
    now = now or utc_now_dt()
    try:
        cls = action_class(action_type)
        state = load_state(run_dir).current_state
        summary = load_approval_registry(run_dir, now)
    except (ApprovalValidationError, StateValidationError) as exc:
        return ActionDecision(
            action_type,
            None,
            "error",
            None,
            candidate,
            None,
            None,
            None,
            None,
            False,
            None,
            None,
            str(exc),
        )
    if cls == "prohibited":
        return ActionDecision(
            action_type,
            cls,
            "deny",
            state,
            candidate,
            None,
            None,
            None,
            None,
            False,
            None,
            None,
            "prohibited action category is permanently denied",
        )
    if state not in ALLOWED_STATES.get(action_type, set()):
        return ActionDecision(
            action_type,
            cls,
            "deny",
            state,
            candidate,
            None,
            None,
            None,
            None,
            action_type in APPROVABLE,
            None,
            None,
            f"action is not permitted in state {state}",
        )
    requires_candidate = action_type != "local_analysis"
    if requires_candidate and not candidate:
        return ActionDecision(
            action_type,
            cls,
            "error",
            state,
            candidate,
            None,
            None,
            None,
            None,
            action_type in APPROVABLE,
            None,
            None,
            "candidate is required",
        )
    sd = None
    n = None
    ctype = None
    if candidate:
        try:
            n, ctype = normalize_candidate(candidate)
        except ApprovalValidationError as exc:
            return ActionDecision(
                action_type,
                cls,
                "error",
                state,
                candidate,
                None,
                None,
                None,
                None,
                action_type in APPROVABLE,
                None,
                None,
                str(exc),
            )
        sd = evaluate_scope_path(run_dir, candidate)
        if sd.decision == "error":
            return ActionDecision(
                action_type,
                cls,
                "error",
                state,
                candidate,
                sd.normalized_candidate,
                sd.candidate_type,
                sd.decision,
                sd.matched_rule,
                action_type in APPROVABLE,
                None,
                None,
                sd.reason,
            )
        if sd.decision != "allow":
            return ActionDecision(
                action_type,
                cls,
                "deny",
                state,
                candidate,
                sd.normalized_candidate,
                sd.candidate_type,
                sd.decision,
                sd.matched_rule,
                action_type in APPROVABLE,
                None,
                None,
                "candidate is outside scope",
            )
    if action_type not in APPROVABLE:
        return ActionDecision(
            action_type,
            cls,
            "allow",
            state,
            candidate,
            n,
            ctype,
            sd.decision if sd else None,
            sd.matched_rule if sd else None,
            False,
            None,
            None,
            "approval is not required",
        )
    matches = [
        a
        for a in summary.approvals
        if a.status == "active" and a.action_type == action_type and a.candidate == n
    ]
    if not matches:
        return ActionDecision(
            action_type,
            cls,
            "deny",
            state,
            candidate,
            n,
            ctype,
            sd.decision if sd else None,
            sd.matched_rule if sd else None,
            True,
            None,
            "missing",
            "no active exact matching approval",
        )
    m = matches[-1]
    return ActionDecision(
        action_type,
        cls,
        "allow",
        state,
        candidate,
        n,
        ctype,
        sd.decision if sd else None,
        sd.matched_rule if sd else None,
        True,
        m.approval_id,
        "active",
        "active exact matching approval exists",
    )
