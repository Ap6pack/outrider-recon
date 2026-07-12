from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from outrider.approval import ApprovalPolicyError, ApprovalValidationError, evaluate_action, grant_approval, list_approvals, revoke_approval
from outrider.evidence import EvidenceRefusalError, EvidenceRegistrationError, EvidenceValidationError, load_evidence_registry, register_evidence, verify_all_evidence
from outrider.scope import evaluate_scope_path
from outrider.state import InvalidTransitionError, StateValidationError, bootstrap_legacy_run, initialize_state, load_state, transition_state


DEFAULT_FILES = {
    "assets.json": {"assets": [], "notes": "Discovered assets will be stored here."},
    "web_surface.json": {"hosts": [], "apis": [], "interesting_paths": [], "notes": "Web and API surface observations will be stored here."},
    "identity_fabric.json": {"providers": [], "tenants": [], "domains": [], "notes": "Identity, federation, and SaaS observations will be stored here."},
    "bb_intel.json": {"matches": [], "notes": "Public disclosure intelligence matches will be stored here."},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_run_name(name: str) -> str:
    return name.strip().replace("https://", "").replace("http://", "").strip("/")


def write_if_missing(path: Path, content: str) -> bool:
    if path.exists():
        return False
    path.write_text(content, encoding="utf-8")
    return True


def append_jsonl(path: Path, event: dict) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def render_scope_yaml(target: str, scopes: Iterable[str], exclusions: Iterable[str]) -> str:
    scope_lines = "\n".join(f"  - {json.dumps(item)}" for item in scopes) or "  - TODO"
    exclusion_items = list(exclusions)
    if exclusion_items:
        exclusion_block = "out_of_scope:\n" + "\n".join(f"  - {json.dumps(item)}" for item in exclusion_items)
    else:
        exclusion_block = "out_of_scope: []"
    return f"""target: {target}
created_at: {utc_now()}
engagement_type: authorized_external_recon
boundary:
  - read_only_recon_by_default
  - explicit_rules_of_engagement_required_for_post_discovery
  - no_destructive_validation_without_written_authorization
in_scope:
{scope_lines}
{exclusion_block}
traffic_tagging:
  user_agent: TODO
  source_ip: TODO
notes:
  - Replace TODO values before using this run folder for real work.
"""


def render_findings_md(target: str) -> str:
    return f"""# Finding Cards — {target}

This file is the operator-facing finding card output for the run.

## Finding template

```text
[SEVERITY] asset.example exposes interesting surface

Asset:
- https://asset.example/path

Confidence:
- Suspected | Firm | Confirmed

Evidence:
- Observation
- Timestamp
- Saved artifact path or hash

Why it matters:
- Explain the security relevance.
- Explain why this asset outranks lower-priority leads.
- Reference public disclosure intelligence when useful.

Recommended handoff:
- Manual review
- Proxy-assisted validation
- ASM ticket
- Client remediation note
- Deeper active testing under written authorization

Safe next step:
- State the next bounded action.
- Use owned test accounts only when applicable.
- Stop before destructive writes, privilege changes, or data modification unless explicitly authorized.
```
"""


def render_technique_cards_md(target: str) -> str:
    return f"""# Technique Cards — {target}

Technique cards map discovered surface area to known public disclosure patterns.

## Technique template

```text
Technique Card: observed surface → review path

Matched because:
- What Outrider observed.
- Why the surface resembles prior public reports.
- What makes it worth prioritizing.

Prior disclosure pattern:
- Short explanation of the relevant public report pattern.
- No exploit instructions.
- Focus on triage, evidence, and safe review.

Recommended safe probes:
- Confirm the observation.
- Collect evidence.
- Validate only within written authorization.
- Stop before destructive actions or unauthorized access.

Confidence: Suspected | Firm | Confirmed
Value: Low | Medium | High
Handoff: Where this should go next
```
"""


def render_surface_md(target: str) -> str:
    return f"""# Ranked Surface — {target}

## P1 — investigate first

_No P1 leads recorded yet._

## P2 — useful, but not first

_No P2 leads recorded yet._

## Low priority / kill

_No low-priority assets recorded yet._

## Notes

Use this file to explain why assets were ranked, not just what was discovered.
"""


def render_report_md(target: str) -> str:
    return f"""# Outrider Recon Report — {target}

## Executive summary

TODO: Summarize the highest-value recon leads, why they matter, and what should happen next.

## Scope

See `scope.yaml`.

## High-priority leads

TODO: Add summarized P1 findings.

## Evidence

TODO: Reference saved artifacts, timestamps, and hashes.

## Recommended next steps

TODO: Add safe handoff recommendations.

## Boundary statement

No destructive validation should be performed unless explicitly authorized in the rules of engagement.
"""


def init_run(args: argparse.Namespace) -> int:
    target = normalize_run_name(args.target)
    run_dir = Path(args.output_dir) / target
    run_dir.mkdir(parents=True, exist_ok=True)
    created = []

    if write_if_missing(run_dir / "scope.yaml", render_scope_yaml(target, args.scope or [target], args.exclude or [])):
        created.append("scope.yaml")

    run_jsonl = run_dir / "run.jsonl"
    if not run_jsonl.exists():
        run_jsonl.touch()
        created.append("run.jsonl")

    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        if run_jsonl.read_text(encoding="utf-8").strip():
            print("Legacy run folder detected without manifest.json; use `outrider state bootstrap` to create state tracking.")
        else:
            initialize_state(run_dir, target, args.actor, args.authorization_reference)
            created.append("manifest.json")


    for filename, payload in DEFAULT_FILES.items():
        if write_if_missing(run_dir / filename, json.dumps(payload, indent=2, sort_keys=True) + "\n"):
            created.append(filename)

    if write_if_missing(run_dir / "evidence.jsonl", ""):
        created.append("evidence.jsonl")
    if write_if_missing(run_dir / "approvals.jsonl", ""):
        created.append("approvals.jsonl")
    artifacts_dir = run_dir / "artifacts"
    if not artifacts_dir.exists():
        artifacts_dir.mkdir()
        created.append("artifacts/")

    markdown_files = {
        "findings.md": render_findings_md(target),
        "technique_cards.md": render_technique_cards_md(target),
        "surface.md": render_surface_md(target),
        "report.md": render_report_md(target),
    }

    for filename, content in markdown_files.items():
        if write_if_missing(run_dir / filename, content):
            created.append(filename)

    print(f"Initialized Outrider run: {run_dir}")
    if created:
        print("Created:")
        for item in created:
            print(f"  - {item}")
    else:
        print("No files created; run folder already existed.")
    return 0


def show_run(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"Run folder not found: {run_dir}")
        return 1
    expected = ["manifest.json", "scope.yaml", "run.jsonl", "evidence.jsonl", "approvals.jsonl", "artifacts/", "assets.json", "web_surface.json", "identity_fabric.json", "bb_intel.json", "findings.md", "technique_cards.md", "surface.md", "report.md"]
    print(f"Outrider run: {run_dir}")
    for filename in expected:
        marker = "ok" if (run_dir / filename.rstrip("/")).exists() else "missing"
        print(f"  [{marker}] {filename}")
    try:
        print(f"State: {load_state(run_dir).current_state}")
    except StateValidationError as exc:
        if not (run_dir / "manifest.json").exists():
            print("State: unavailable (legacy run folder without manifest.json)")
        else:
            print(f"State: invalid ({exc})")
    return 0


def _print_state_summary(summary, as_json: bool) -> None:
    if as_json:
        print(json.dumps(summary.to_dict(), sort_keys=True))
        return
    print(f"Run ID: {summary.run_id}")
    print(f"Target: {summary.target}")
    print(f"Current state: {summary.current_state}")
    print(f"Event count: {summary.event_count}")
    print(f"Created time: {summary.created_at}")
    print(f"Last transition time: {summary.last_transition_at or 'n/a'}")
    print(f"Last actor: {summary.last_actor or 'n/a'}")
    print(f"Legacy events detected: {summary.legacy_events_detected}")
    if summary.legacy_events_detected:
        print(f"Legacy event count: {summary.legacy_event_count}")


def state_show(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"ERROR: run folder not found: {run_dir}")
        return 2
    if not (run_dir / "manifest.json").exists():
        if args.json:
            print(json.dumps({"state_available": False, "message": "legacy run folder without manifest.json", "run_dir": str(run_dir)}, sort_keys=True))
        else:
            print("State tracking unavailable: legacy run folder without manifest.json. Use `outrider state bootstrap`.")
        return 0
    try:
        _print_state_summary(load_state(run_dir), args.json)
        return 0
    except StateValidationError as exc:
        print(f"ERROR: {exc}")
        return 2


def state_transition(args: argparse.Namespace) -> int:
    try:
        _print_state_summary(transition_state(args.run_dir, args.new_state, args.actor, args.reason), args.json)
        return 0
    except InvalidTransitionError as exc:
        print(f"ERROR: {exc}")
        return 1
    except StateValidationError as exc:
        print(f"ERROR: {exc}")
        return 2


def state_bootstrap(args: argparse.Namespace) -> int:
    try:
        summary = bootstrap_legacy_run(args.run_dir, args.target, args.actor, args.authorization_reference)
        if args.json:
            payload = summary.to_dict(); payload["legacy_lines_preserved"] = True
            print(json.dumps(payload, sort_keys=True))
        else:
            _print_state_summary(summary, False)
            print("Legacy run.jsonl lines preserved.")
        return 0
    except InvalidTransitionError as exc:
        print(f"ERROR: {exc}")
        return 1
    except StateValidationError as exc:
        print(f"ERROR: {exc}")
        return 2


def scope_check(args: argparse.Namespace) -> int:
    decision = evaluate_scope_path(args.run_dir, args.candidate)
    if args.json:
        print(json.dumps(decision.to_dict(), sort_keys=True))
    else:
        print(decision.decision.upper())
        print(f"Normalized candidate: {decision.normalized_candidate or 'n/a'}")
        print(f"Matched rule: {decision.matched_rule or 'none'}")
        print(f"Matched rule source: {decision.matched_rule_source}")
        print(f"Reason: {decision.reason}")
    if decision.decision == "allow":
        return 0
    if decision.decision == "deny":
        return 1
    return 2


def evidence_register(args: argparse.Namespace) -> int:
    try:
        record = register_evidence(args.run_dir, args.relative_path, args.actor, args.artifact_type, args.media_type, args.source, args.note)
        if args.json:
            print(json.dumps(record.to_dict(), sort_keys=True))
        else:
            print(f"Evidence ID: {record.evidence_id}")
            print(f"Run ID: {record.run_id}")
            print(f"Path: {record.path}")
            print(f"Artifact type: {record.artifact_type}")
            print(f"SHA-256: {record.sha256}")
            print(f"Size: {record.size_bytes}")
            print(f"Actor: {record.actor}")
        return 0
    except EvidenceRefusalError as exc:
        print(f"ERROR: {exc}")
        return 1
    except (EvidenceRegistrationError, EvidenceValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


def evidence_list(args: argparse.Namespace) -> int:
    try:
        load_state(args.run_dir)
        summary = load_evidence_registry(args.run_dir)
        if args.json:
            print(json.dumps(summary.to_dict(), sort_keys=True))
        else:
            print(f"Run ID: {summary.run_id}")
            print(f"Evidence count: {summary.evidence_count}")
            for record in summary.records:
                print(f"{record.sequence} {record.evidence_id} {record.path} {record.artifact_type} {record.sha256} {record.size_bytes} {record.actor} {record.registered_at}")
        return 0
    except (EvidenceValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


def evidence_verify(args: argparse.Namespace) -> int:
    try:
        results = verify_all_evidence(args.run_dir, args.evidence_id)
        payload = {"results": [r.to_dict() for r in results], "verified": all(r.status == "verified" for r in results)}
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            for r in results:
                print(f"Evidence ID: {r.evidence_id}")
                print(f"Path: {r.path or 'n/a'}")
                print(f"Expected SHA-256: {r.expected_sha256 or 'n/a'}")
                print(f"Actual SHA-256: {r.actual_sha256 or 'n/a'}")
                print(f"Expected size: {r.expected_size}")
                print(f"Actual size: {r.actual_size if r.actual_size is not None else 'n/a'}")
                print(f"Status: {r.status}")
                print(f"Reason: {r.reason}")
        return 0 if payload["verified"] else 1
    except (EvidenceValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2



def _print_approval_grant(grant, as_json: bool) -> None:
    if as_json:
        print(json.dumps(grant.to_dict(), sort_keys=True)); return
    print(f"Approval ID: {grant.approval_id}")
    print(f"Run ID: {grant.run_id}")
    print(f"Action type: {grant.action_type}")
    print(f"Normalized candidate: {grant.candidate}")
    print(f"Actor: {grant.actor}")
    print(f"Granted at: {grant.occurred_at}")
    print(f"Expires at: {grant.expires_at}")
    print(f"Reason: {grant.reason}")
    if grant.conditions:
        print(f"Conditions: {grant.conditions}")
    print(f"Status: {grant.status}")


def approval_grant(args: argparse.Namespace) -> int:
    try:
        grant = grant_approval(args.run_dir, args.action_type, args.candidate, args.actor, args.reason, duration_minutes=args.duration_minutes, expires_at=args.expires_at, conditions=args.conditions)
        _print_approval_grant(grant, args.json); return 0
    except ApprovalPolicyError as exc:
        print(f"ERROR: {exc}"); return 1
    except (ApprovalValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}"); return 2


def approval_revoke(args: argparse.Namespace) -> int:
    try:
        event = revoke_approval(args.run_dir, args.approval_id, args.actor, args.reason)
        if args.json: print(json.dumps(event.to_dict(), sort_keys=True))
        else:
            print(f"Revoked approval: {event.approval_id}")
            print(f"Run ID: {event.run_id}")
            print(f"Actor: {event.actor}")
            print(f"Revoked at: {event.occurred_at}")
            print(f"Reason: {event.reason}")
        return 0
    except ApprovalPolicyError as exc:
        print(f"ERROR: {exc}"); return 1
    except (ApprovalValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}"); return 2


def approval_list(args: argparse.Namespace) -> int:
    try:
        summary = list_approvals(args.run_dir)
        if args.json: print(json.dumps(summary.to_dict(), sort_keys=True))
        else:
            print(f"Run ID: {summary.run_id}")
            print(f"Approval count: {summary.approval_count}")
            print(f"Active: {summary.active_count} Expired: {summary.expired_count} Revoked: {summary.revoked_count}")
            for a in summary.approvals:
                rev = f" revoked_at={a.revoked_at} revoked_by={a.revoked_by} revocation_reason={a.revocation_reason}" if a.status == "revoked" else ""
                print(f"{a.sequence} {a.approval_id} {a.action_type} {a.candidate} {a.actor} {a.occurred_at} {a.expires_at} {a.status}{rev}")
        return 0
    except (ApprovalValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}"); return 2


def action_check(args: argparse.Namespace) -> int:
    decision = evaluate_action(args.run_dir, args.action_type, args.candidate)
    if args.json:
        print(json.dumps(decision.to_dict(), sort_keys=True))
    else:
        print(decision.decision.upper())
        print(f"Action type: {decision.action_type}")
        print(f"Action class: {decision.action_class or 'n/a'}")
        print(f"Workflow state: {decision.workflow_state or 'n/a'}")
        print(f"Normalized candidate: {decision.normalized_candidate or 'n/a'}")
        print(f"Scope result: {decision.scope_decision or 'n/a'}")
        print(f"Matched scope rule: {decision.matched_scope_rule or 'none'}")
        print(f"Approval required: {decision.approval_required}")
        print(f"Matched approval ID: {decision.matched_approval_id or 'none'}")
        print(f"Reason: {decision.reason}")
    return 0 if decision.decision == "allow" else 1 if decision.decision == "deny" else 2

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="outrider", description="Outrider Recon CLI harness for run-folder creation and evidence-backed handoff.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    init_parser = subcommands.add_parser("init", help="Create a new Outrider run folder.")
    init_parser.add_argument("target", help="Target/run name, for example acme.example.")
    init_parser.add_argument("--scope", action="append", help="Authorized in-scope domain or pattern. Repeat for multiple values.")
    init_parser.add_argument("--exclude", action="append", help="Out-of-scope domain or pattern. Repeat for multiple values.")
    init_parser.add_argument("--output-dir", default="runs", help="Base output directory. Defaults to ./runs.")
    init_parser.add_argument("--actor", help="Operator creating the run manifest.")
    init_parser.add_argument("--authorization-reference", help="Opaque authorization reference metadata.")
    init_parser.set_defaults(func=init_run)

    show_parser = subcommands.add_parser("show", help="Show expected files for a run folder.")
    show_parser.add_argument("run_dir", help="Run folder path, for example runs/acme.example.")
    show_parser.set_defaults(func=show_run)

    scope_parser = subcommands.add_parser("scope-check", help="Evaluate a candidate against a run folder's scope.yaml.")
    scope_parser.add_argument("run_dir", help="Run folder path containing scope.yaml.")
    scope_parser.add_argument("candidate", help="Domain, IP address, or URL to evaluate.")
    scope_parser.add_argument("--json", action="store_true", help="Emit the structured scope decision as JSON.")
    scope_parser.set_defaults(func=scope_check)

    state_parser = subcommands.add_parser("state", help="Show or transition durable run workflow state.")
    state_sub = state_parser.add_subparsers(dest="state_command", required=True)
    state_show_parser = state_sub.add_parser("show", help="Show durable run state.")
    state_show_parser.add_argument("run_dir")
    state_show_parser.add_argument("--json", action="store_true")
    state_show_parser.set_defaults(func=state_show)
    transition_parser = state_sub.add_parser("transition", help="Append a validated state transition.")
    transition_parser.add_argument("run_dir")
    transition_parser.add_argument("new_state")
    transition_parser.add_argument("--actor", required=True)
    transition_parser.add_argument("--reason")
    transition_parser.add_argument("--json", action="store_true")
    transition_parser.set_defaults(func=state_transition)
    bootstrap_parser = state_sub.add_parser("bootstrap", help="Bootstrap state tracking for a legacy run folder.")
    bootstrap_parser.add_argument("run_dir")
    bootstrap_parser.add_argument("--target", required=True)
    bootstrap_parser.add_argument("--actor", required=True)
    bootstrap_parser.add_argument("--authorization-reference")
    bootstrap_parser.add_argument("--json", action="store_true")
    bootstrap_parser.set_defaults(func=state_bootstrap)


    approval_parser = subcommands.add_parser("approval", help="Grant, revoke, and list offline human approvals.")
    approval_sub = approval_parser.add_subparsers(dest="approval_command", required=True)
    approval_grant_parser = approval_sub.add_parser("grant", help="Append a time-bounded approval grant.")
    approval_grant_parser.add_argument("run_dir")
    approval_grant_parser.add_argument("action_type")
    approval_grant_parser.add_argument("candidate")
    approval_grant_parser.add_argument("--actor", required=True)
    approval_grant_parser.add_argument("--reason", required=True)
    expiry = approval_grant_parser.add_mutually_exclusive_group(required=True)
    expiry.add_argument("--duration-minutes", type=int)
    expiry.add_argument("--expires-at")
    approval_grant_parser.add_argument("--conditions")
    approval_grant_parser.add_argument("--json", action="store_true")
    approval_grant_parser.set_defaults(func=approval_grant)
    approval_revoke_parser = approval_sub.add_parser("revoke", help="Append an approval revocation.")
    approval_revoke_parser.add_argument("run_dir")
    approval_revoke_parser.add_argument("approval_id")
    approval_revoke_parser.add_argument("--actor", required=True)
    approval_revoke_parser.add_argument("--reason", required=True)
    approval_revoke_parser.add_argument("--json", action="store_true")
    approval_revoke_parser.set_defaults(func=approval_revoke)
    approval_list_parser = approval_sub.add_parser("list", help="List derived approval status.")
    approval_list_parser.add_argument("run_dir")
    approval_list_parser.add_argument("--json", action="store_true")
    approval_list_parser.set_defaults(func=approval_list)

    action_parser = subcommands.add_parser("action-check", help="Evaluate an offline action policy decision.")
    action_parser.add_argument("run_dir")
    action_parser.add_argument("action_type")
    action_parser.add_argument("--candidate")
    action_parser.add_argument("--json", action="store_true")
    action_parser.set_defaults(func=action_check)

    evidence_parser = subcommands.add_parser("evidence", help="Register, list, and verify local run evidence.")
    evidence_sub = evidence_parser.add_subparsers(dest="evidence_command", required=True)
    evidence_register_parser = evidence_sub.add_parser("register", help="Append an evidence registration record.")
    evidence_register_parser.add_argument("run_dir")
    evidence_register_parser.add_argument("relative_path")
    evidence_register_parser.add_argument("--actor", required=True)
    evidence_register_parser.add_argument("--type", dest="artifact_type", required=True)
    evidence_register_parser.add_argument("--media-type")
    evidence_register_parser.add_argument("--source")
    evidence_register_parser.add_argument("--note")
    evidence_register_parser.add_argument("--json", action="store_true")
    evidence_register_parser.set_defaults(func=evidence_register)
    evidence_list_parser = evidence_sub.add_parser("list", help="List registered evidence.")
    evidence_list_parser.add_argument("run_dir")
    evidence_list_parser.add_argument("--json", action="store_true")
    evidence_list_parser.set_defaults(func=evidence_list)
    evidence_verify_parser = evidence_sub.add_parser("verify", help="Verify registered evidence artifacts.")
    evidence_verify_parser.add_argument("run_dir")
    evidence_verify_parser.add_argument("--evidence-id")
    evidence_verify_parser.add_argument("--json", action="store_true")
    evidence_verify_parser.set_defaults(func=evidence_verify)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
