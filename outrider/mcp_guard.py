from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Literal
import re

from outrider.approval import ACTION_TYPES, evaluate_action
from outrider.scope import ScopeValidationError, _normalize_candidate
from outrider.state import StateValidationError, load_manifest, load_state

Decision = Literal["allow", "deny", "error"]
CandidateSource = Literal["domain_argument", "manifest_target"]

_DOMAIN_TOOLS = {"crtsh_lookup", "hudsonrock_lookup", "wayback_urls", "dns_records"}
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class MCPGuardError(ValueError):
    pass


@dataclass(frozen=True)
class MCPToolPolicy:
    tool_name: str
    action_type: str
    candidate_source: CandidateSource
    candidate_must_be_domain: bool = True


@dataclass(frozen=True)
class MCPGuardDecision:
    tool: str
    action_type: str | None
    action_class: str | None
    decision: Decision
    run_id: str | None
    workflow_state: str | None
    original_policy_candidate: str | None
    normalized_policy_candidate: str | None
    candidate_type: str | None
    scope_decision: str | None
    matched_scope_rule: str | None
    approval_required: bool
    matched_approval_id: str | None
    approval_status: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


TOOL_POLICIES: dict[str, MCPToolPolicy] = {
    "crtsh_lookup": MCPToolPolicy("crtsh_lookup", "public_source_lookup", "domain_argument"),
    "hudsonrock_lookup": MCPToolPolicy("hudsonrock_lookup", "public_source_lookup", "domain_argument"),
    "wayback_urls": MCPToolPolicy("wayback_urls", "public_source_lookup", "domain_argument"),
    "dns_records": MCPToolPolicy("dns_records", "target_enumeration", "domain_argument"),
    "epss_score": MCPToolPolicy("epss_score", "public_source_lookup", "manifest_target"),
}


def normalize_domain_candidate(candidate: str) -> str:
    if not isinstance(candidate, str):
        raise MCPGuardError("domain must be a string")
    text = candidate.strip().lower()
    if not text:
        raise MCPGuardError("domain must not be empty")
    if "://" in text or any(ch in text for ch in "/?#@"):
        raise MCPGuardError("domain must be a domain name, not a URL, path, query, fragment, or credential-bearing value")
    if ":" in text:
        raise MCPGuardError("domain must not include a port")
    if text.startswith("*.") or "*" in text:
        raise MCPGuardError("domain must be an exact domain, not a wildcard")
    if text.endswith("."):
        text = text[:-1]
    if not text:
        raise MCPGuardError("domain must not be empty")
    try:
        ip_address(text)
    except ValueError:
        pass
    else:
        raise MCPGuardError("domain must not be an IP address")
    labels = text.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels) or len(text) > 253:
        raise MCPGuardError("domain is malformed")
    return text


def _error_decision(tool_name: str, policy: MCPToolPolicy | None, reason: str, *, run_id: str | None = None, workflow_state: str | None = None, original: str | None = None, normalized: str | None = None, candidate_type: str | None = None) -> MCPGuardDecision:
    return MCPGuardDecision(
        tool=tool_name,
        action_type=policy.action_type if policy else None,
        action_class=None,
        decision="error",
        run_id=run_id,
        workflow_state=workflow_state,
        original_policy_candidate=original,
        normalized_policy_candidate=normalized,
        candidate_type=candidate_type,
        scope_decision=None,
        matched_scope_rule=None,
        approval_required=policy.action_type in {"target_read_only_request", "target_enumeration", "intrusive_validation"} if policy else False,
        matched_approval_id=None,
        approval_status=None,
        reason=reason,
    )


def _safe_reason(exc: Exception) -> str:
    # Avoid leaking local run-directory paths to MCP clients.
    text = str(exc)
    for marker in ("manifest.json", "scope.yaml", "run.jsonl", "approvals.jsonl"):
        if marker in text and "not found" in text:
            return f"{marker} not found"
        if marker in text and "could not read" in text:
            return f"could not read {marker}"
        if marker in text:
            return text.split(": /", 1)[0]
    return text


def authorize_mcp_tool(tool_name: str, run_dir: str | Path, *, domain: str | None = None, now: Any = None) -> MCPGuardDecision:
    policy = TOOL_POLICIES.get(tool_name)
    if policy is None:
        return _error_decision(tool_name, None, "unknown MCP tool")
    if not isinstance(run_dir, (str, Path)) or not str(run_dir):
        return _error_decision(tool_name, policy, "run_dir is required")

    try:
        manifest = load_manifest(run_dir)
        state = load_state(run_dir)
    except (StateValidationError, OSError) as exc:
        return _error_decision(tool_name, policy, _safe_reason(exc))

    original: str | None
    if policy.candidate_source == "manifest_target":
        original = manifest.target
    else:
        original = domain

    try:
        normalized = normalize_domain_candidate(original)  # type: ignore[arg-type]
    except MCPGuardError as exc:
        return _error_decision(
            tool_name, policy, str(exc), run_id=manifest.run_id, workflow_state=state.current_state, original=original
        )

    try:
        scope_normalized, candidate_type, _ = _normalize_candidate(normalized)
    except ScopeValidationError as exc:
        return _error_decision(
            tool_name, policy, str(exc), run_id=manifest.run_id, workflow_state=state.current_state, original=original, normalized=normalized
        )
    if candidate_type != "domain":
        return _error_decision(
            tool_name, policy, "policy candidate must be a domain", run_id=manifest.run_id, workflow_state=state.current_state, original=original, normalized=scope_normalized, candidate_type=candidate_type
        )

    if policy.action_type not in ACTION_TYPES:
        return _error_decision(tool_name, policy, "unknown mapped action type", run_id=manifest.run_id, workflow_state=state.current_state, original=original, normalized=scope_normalized, candidate_type=candidate_type)

    try:
        action = evaluate_action(run_dir, policy.action_type, scope_normalized, now=now)
    except Exception as exc:
        return _error_decision(tool_name, policy, _safe_reason(exc), run_id=manifest.run_id, workflow_state=state.current_state, original=original, normalized=scope_normalized, candidate_type=candidate_type)

    return MCPGuardDecision(
        tool=tool_name,
        action_type=policy.action_type,
        action_class=action.action_class,
        decision=action.decision,
        run_id=manifest.run_id,
        workflow_state=action.workflow_state or state.current_state,
        original_policy_candidate=original,
        normalized_policy_candidate=action.normalized_candidate or scope_normalized,
        candidate_type=action.candidate_type or candidate_type,
        scope_decision=action.scope_decision,
        matched_scope_rule=action.matched_scope_rule,
        approval_required=action.approval_required,
        matched_approval_id=action.matched_approval_id,
        approval_status=action.approval_status,
        reason=action.reason,
    )
