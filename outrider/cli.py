from __future__ import annotations

import argparse
import json
import socket
import threading
import time
import webbrowser
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from outrider.approval import (
    ApprovalPolicyError,
    ApprovalValidationError,
    evaluate_action,
    grant_approval,
    list_approvals,
    revoke_approval,
)
from outrider.finding import (
    FindingPromotionRefusal,
    FindingValidationError,
    get_finding,
    list_findings,
    promote_finding,
    verify_all_findings,
)
from outrider.evidence import (
    EvidenceRefusalError,
    EvidenceRegistrationError,
    EvidenceValidationError,
    load_evidence_registry,
    register_evidence,
    verify_all_evidence,
)
from outrider.scope import evaluate_scope_path
from outrider.run_setup import DEFAULT_FILES, render_scope_yaml, render_findings_md, render_technique_cards_md, render_surface_md, render_report_md, utc_now
from outrider.skill_contract import (
    SkillContractValidationError,
    create_skill_request,
    validate_skill_request,
    validate_skill_result,
)
from outrider.state import (
    InvalidTransitionError,
    StateValidationError,
    bootstrap_legacy_run,
    initialize_state,
    load_state,
    transition_state,
)
from outrider.orchestrator import (
    OrchestrationBounds,
    SeedRequest,
    orchestration_status,
    run_orchestration,
)
from outrider.executors import ClaudeSubprocessExecutor, ExecutorError
from outrider.verifier import VerifierError, verification_summary, verify_candidates


LOOPBACK_WEB_HOSTS = {"127.0.0.1", "localhost", "::1"}

def package_version() -> str:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if pyproject.exists():
        return next(line.split("=", 1)[1].strip().strip("\"'") for line in pyproject.read_text(encoding="utf-8").splitlines() if line.strip().startswith("version ="))
    try:
        return version("outrider-recon")
    except PackageNotFoundError:  # pragma: no cover - installed metadata should normally exist
        return "0.2.0"

def _valid_web_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer from 1024 through 65535") from exc
    if port < 1024 or port > 65535:
        raise argparse.ArgumentTypeError("port must be an integer from 1024 through 65535")
    return port

def _validate_web_args(args: argparse.Namespace) -> Path:
    if args.host not in LOOPBACK_WEB_HOSTS:
        raise ValueError("web host must be one of 127.0.0.1, localhost, or ::1")
    root = Path(args.runs_root)
    if root.is_symlink():
        raise ValueError("RUNS_ROOT must not be a symlink")
    if not root.exists():
        raise ValueError("RUNS_ROOT does not exist")
    if not root.is_dir():
        raise ValueError("RUNS_ROOT must be a directory")
    return root

def _safe_default_runs_root(path: str | Path) -> Path:
    root = Path(path)
    if root.is_symlink():
        raise ValueError("runs root must not be a symlink")
    if root.exists() and not root.is_dir():
        raise ValueError("runs root must be a directory")
    if not root.exists():
        root.mkdir(parents=True, exist_ok=False)
    return root

def _browser_url(host: str, port: int) -> str:
    return f"http://{host}:{port}" if host != "::1" else f"http://[::1]:{port}"

def _wait_for_loopback(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    connect_host = "::1" if host == "::1" else host
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((connect_host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False

def _open_browser_when_ready(host: str, port: int, opener=webbrowser.open, printer=print) -> threading.Thread:
    url = _browser_url(host, port)
    def worker() -> None:
        if not _wait_for_loopback(host, port):
            printer(f"Open your browser to {url}")
            return
        try:
            if not opener(url):
                printer(f"Open your browser to {url}")
        except Exception:
            printer(f"Open your browser to {url}")
    thread = threading.Thread(target=worker, name="outrider-browser-open", daemon=True)
    thread.start()
    return thread

def launch_local_portal(args: argparse.Namespace, *, create_default_root: bool = False, browser_opener=webbrowser.open) -> int:
    try:
        if args.host not in LOOPBACK_WEB_HOSTS:
            raise ValueError("web host must be one of 127.0.0.1, localhost, or ::1")
        root = _safe_default_runs_root(args.runs_root) if create_default_root else _validate_web_args(args)
        try:
            import uvicorn
            from outrider.web_app import create_app
        except ImportError:
            print('The Outrider web portal is not installed.')
            print('Run:')
            print('python -m pip install -e ".[web]"')
            return 2
        if getattr(args, "enable_mcp_enrichment", False):
            try:
                import httpx  # noqa: F401
            except ImportError:
                print('Discovery enrichment dependencies are not installed.')
                print('Run:')
                print('python -m pip install -e ".[web,enrichment]"')
                return 2
        app = create_app(root, mcp_enrichment_enabled=getattr(args, "enable_mcp_enrichment", False))
        url = _browser_url(args.host, args.port)
        print("Outrider is running locally:")
        print(url)
        print()
        if getattr(args, "no_browser", False):
            print("Browser opening disabled. Open the local URL above.")
        else:
            print("Opening your browser…")
            _open_browser_when_ready(args.host, args.port, opener=browser_opener)
        print("Press Ctrl+C to stop Outrider.")
        print()
        print("Authentication: none")
        print("Network access: loopback only")
        if getattr(args, "enable_mcp_enrichment", False):
            print("Discovery enrichment: explicitly enabled")
            print("Results remain transient unless the operator explicitly saves them later.")
        else:
            print("Discovery enrichment: disabled")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 2
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 2

def web_serve(args: argparse.Namespace) -> int:
    return launch_local_portal(args, create_default_root=False)



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

def init_run(args: argparse.Namespace) -> int:
    target = normalize_run_name(args.target)
    run_dir = Path(args.output_dir) / target
    run_dir.mkdir(parents=True, exist_ok=True)
    created = []

    if write_if_missing(
        run_dir / "scope.yaml",
        render_scope_yaml(target, args.scope or [target], args.exclude or []),
    ):
        created.append("scope.yaml")

    run_jsonl = run_dir / "run.jsonl"
    if not run_jsonl.exists():
        run_jsonl.touch()
        created.append("run.jsonl")

    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        if run_jsonl.read_text(encoding="utf-8").strip():
            print(
                "Legacy run folder detected without manifest.json; use `outrider state bootstrap` to create state tracking."
            )
        else:
            initialize_state(run_dir, target, args.actor, args.authorization_reference)
            created.append("manifest.json")

    for filename, payload in DEFAULT_FILES.items():
        if write_if_missing(
            run_dir / filename, json.dumps(payload, indent=2, sort_keys=True) + "\n"
        ):
            created.append(filename)

    if write_if_missing(run_dir / "evidence.jsonl", ""):
        created.append("evidence.jsonl")
    if write_if_missing(run_dir / "approvals.jsonl", ""):
        created.append("approvals.jsonl")
    if write_if_missing(run_dir / "findings.jsonl", ""):
        created.append("findings.jsonl")
    artifacts_dir = run_dir / "artifacts"
    if not artifacts_dir.exists():
        artifacts_dir.mkdir()
        created.append("artifacts/")

    for rel in ["contracts", "contracts/requests", "contracts/results"]:
        path = run_dir / rel
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            created.append(rel + "/")

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
    expected = [
        "manifest.json",
        "scope.yaml",
        "run.jsonl",
        "evidence.jsonl",
        "approvals.jsonl",
        "findings.jsonl",
        "artifacts/",
        "contracts/",
        "contracts/requests/",
        "contracts/results/",
        "assets.json",
        "web_surface.json",
        "identity_fabric.json",
        "bb_intel.json",
        "findings.md",
        "technique_cards.md",
        "surface.md",
        "report.md",
    ]
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
            print(
                json.dumps(
                    {
                        "state_available": False,
                        "message": "legacy run folder without manifest.json",
                        "run_dir": str(run_dir),
                    },
                    sort_keys=True,
                )
            )
        else:
            print(
                "State tracking unavailable: legacy run folder without manifest.json. Use `outrider state bootstrap`."
            )
        return 0
    try:
        _print_state_summary(load_state(run_dir), args.json)
        return 0
    except StateValidationError as exc:
        print(f"ERROR: {exc}")
        return 2


def state_transition(args: argparse.Namespace) -> int:
    try:
        _print_state_summary(
            transition_state(args.run_dir, args.new_state, args.actor, args.reason),
            args.json,
        )
        return 0
    except InvalidTransitionError as exc:
        print(f"ERROR: {exc}")
        return 1
    except StateValidationError as exc:
        print(f"ERROR: {exc}")
        return 2


def state_bootstrap(args: argparse.Namespace) -> int:
    try:
        summary = bootstrap_legacy_run(
            args.run_dir, args.target, args.actor, args.authorization_reference
        )
        if args.json:
            payload = summary.to_dict()
            payload["legacy_lines_preserved"] = True
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
        record = register_evidence(
            args.run_dir,
            args.relative_path,
            args.actor,
            args.artifact_type,
            args.media_type,
            args.source,
            args.note,
        )
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
    except (
        EvidenceRegistrationError,
        EvidenceValidationError,
        StateValidationError,
    ) as exc:
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
                print(
                    f"{record.sequence} {record.evidence_id} {record.path} {record.artifact_type} {record.sha256} {record.size_bytes} {record.actor} {record.registered_at}"
                )
        return 0
    except (EvidenceValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


def evidence_verify(args: argparse.Namespace) -> int:
    try:
        results = verify_all_evidence(args.run_dir, args.evidence_id)
        payload = {
            "results": [r.to_dict() for r in results],
            "verified": all(r.status == "verified" for r in results),
        }
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            for r in results:
                print(f"Evidence ID: {r.evidence_id}")
                print(f"Path: {r.path or 'n/a'}")
                print(f"Expected SHA-256: {r.expected_sha256 or 'n/a'}")
                print(f"Actual SHA-256: {r.actual_sha256 or 'n/a'}")
                print(f"Expected size: {r.expected_size}")
                print(
                    f"Actual size: {r.actual_size if r.actual_size is not None else 'n/a'}"
                )
                print(f"Status: {r.status}")
                print(f"Reason: {r.reason}")
        return 0 if payload["verified"] else 1
    except (EvidenceValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


def _print_approval_grant(grant, as_json: bool) -> None:
    if as_json:
        print(json.dumps(grant.to_dict(), sort_keys=True))
        return
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
        grant = grant_approval(
            args.run_dir,
            args.action_type,
            args.candidate,
            args.actor,
            args.reason,
            duration_minutes=args.duration_minutes,
            expires_at=args.expires_at,
            conditions=args.conditions,
        )
        _print_approval_grant(grant, args.json)
        return 0
    except ApprovalPolicyError as exc:
        print(f"ERROR: {exc}")
        return 1
    except (ApprovalValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


def approval_revoke(args: argparse.Namespace) -> int:
    try:
        event = revoke_approval(args.run_dir, args.approval_id, args.actor, args.reason)
        if args.json:
            print(json.dumps(event.to_dict(), sort_keys=True))
        else:
            print(f"Revoked approval: {event.approval_id}")
            print(f"Run ID: {event.run_id}")
            print(f"Actor: {event.actor}")
            print(f"Revoked at: {event.occurred_at}")
            print(f"Reason: {event.reason}")
        return 0
    except ApprovalPolicyError as exc:
        print(f"ERROR: {exc}")
        return 1
    except (ApprovalValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


def approval_list(args: argparse.Namespace) -> int:
    try:
        summary = list_approvals(args.run_dir)
        if args.json:
            print(json.dumps(summary.to_dict(), sort_keys=True))
        else:
            print(f"Run ID: {summary.run_id}")
            print(f"Approval count: {summary.approval_count}")
            print(
                f"Active: {summary.active_count} Expired: {summary.expired_count} Revoked: {summary.revoked_count}"
            )
            for approval in summary.approvals:
                rev = (
                    f" revoked_at={approval.revoked_at} revoked_by={approval.revoked_by} revocation_reason={approval.revocation_reason}"
                    if approval.status == "revoked"
                    else ""
                )
                print(
                    f"{approval.sequence} {approval.approval_id} {approval.action_type} {approval.candidate} {approval.actor} {approval.occurred_at} {approval.expires_at} {approval.status}{rev}"
                )
        return 0
    except (ApprovalValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


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
    return (
        0 if decision.decision == "allow" else 1 if decision.decision == "deny" else 2
    )



def _print_contract_report(report, as_json: bool) -> None:
    payload = report.to_dict()
    if as_json:
        print(json.dumps(payload, sort_keys=True))
        return
    print(report.overall_status.upper())
    if report.result_id:
        print(f"Result ID: {report.result_id}")
    if report.request_id:
        print(f"Request ID: {report.request_id}")
    if report.run_id:
        print(f"Run ID: {report.run_id}")
    if report.skill:
        print(f"Skill: {report.skill}")
    if report.current_request_policy_decision:
        d = report.current_request_policy_decision
        print(f"Action: {d.get('action_type')}")
        print(f"Normalized candidate: {d.get('normalized_candidate') or 'n/a'}")
        print(f"Current policy decision: {d.get('decision')}")
        print(f"Policy reason: {d.get('reason')}")
    print(f"Evidence count: {report.evidence_count}")
    print(f"Evidence verified: {report.evidence_verified}")
    if report.discovered_candidate_scope_assessments:
        print("Discovered candidate assessments:")
        for d in report.discovered_candidate_scope_assessments:
            print(f"  - {d.get('normalized_candidate') or d.get('original_candidate')}: {d.get('decision')} ({d.get('reason')})")
    if report.recommended_action_policy_assessments:
        print("Recommended action assessments:")
        for d in report.recommended_action_policy_assessments:
            handoff = " handoff_only" if d.get("handoff_only") else ""
            print(f"  - {d.get('action_type')} {d.get('normalized_candidate') or 'n/a'}: {d.get('decision')} ({d.get('reason')}){handoff}")
    if report.errors:
        print("Reason: " + "; ".join(report.errors))


def contract_request_create(args: argparse.Namespace) -> int:
    try:
        req, path, report = create_skill_request(args.run_dir, args.skill, args.actor, args.objective, args.action_type, args.candidate, args.evidence_id or [], args.max_items, args.notes)
        if args.json:
            payload = report.to_dict(); payload["created_file"] = str(path.relative_to(Path(args.run_dir)))
            print(json.dumps(payload, sort_keys=True))
        else:
            _print_contract_report(report, False)
            print(f"Created file: {path.relative_to(Path(args.run_dir))}")
        return 0
    except SkillContractValidationError as exc:
        msg = str(exc)
        print((json.dumps({"error": msg}, sort_keys=True) if args.json else f"ERROR: {msg}"))
        return 1 if "policy" in msg or "evidence" in msg else 2


def contract_request_validate(args: argparse.Namespace) -> int:
    report = validate_skill_request(args.run_dir, args.request_file)
    _print_contract_report(report, args.json)
    if report.overall_status == "valid": return 0
    if report.structural_valid: return 1
    return 2


def contract_result_validate(args: argparse.Namespace) -> int:
    report = validate_skill_result(args.run_dir, args.result_file)
    _print_contract_report(report, args.json)
    if report.overall_status == "valid": return 0
    if report.structural_valid: return 1
    return 2


def _print_finding_record(record, as_json: bool) -> None:
    if as_json:
        print(json.dumps(record.to_dict(), sort_keys=True))
        return
    print(f"Finding ID: {record.finding_id}")
    print(f"Title: {record.title}")
    print(f"Classification: {record.classification}")
    print(f"Affected candidate: {record.affected_candidate}")
    print(f"Severity: {record.severity}")
    print(f"Confidence: {record.confidence}")
    print(f"Promoted by: {record.promoted_by}")
    print(f"Promoted at: {record.promoted_at}")
    print(f"Source result ID: {record.source.result_id}")
    print(f"Source claim ID: {record.source.claim_id}")
    print(f"Evidence count: {len(record.evidence_ids)}")
    print(f"Source result SHA-256: {record.source.result_sha256}")


def finding_promote(args: argparse.Namespace) -> int:
    try:
        record = promote_finding(
            args.run_dir, args.result_file, args.claim_id,
            actor=args.actor, title=args.title, candidate=args.candidate,
            severity=args.severity, confidence=args.confidence,
            validation_basis=args.validation_basis,
            validation_reason=args.validation_reason, impact=args.impact,
            remediation=args.remediation, location=args.location, notes=args.notes,
            supplementary_evidence_ids=args.evidence_id or [],
        )
        _print_finding_record(record, args.json)
        return 0
    except FindingPromotionRefusal as exc:
        print(f"ERROR: {exc}")
        return 1
    except (FindingValidationError, SkillContractValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


def finding_list(args: argparse.Namespace) -> int:
    try:
        summary = list_findings(args.run_dir)
        if args.json:
            print(json.dumps(summary.to_dict(), sort_keys=True))
        else:
            print(f"Run ID: {summary.run_id}")
            print(f"Finding count: {summary.finding_count}")
            for r in summary.records:
                print(f"{r.sequence} {r.finding_id} {r.title} {r.affected_candidate} {r.severity} {r.confidence} {r.source.skill} {r.promoted_at} {r.promoted_by}")
        return 0
    except (FindingValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


def finding_show(args: argparse.Namespace) -> int:
    try:
        record = get_finding(args.run_dir, args.finding_id)
        if record is None:
            print("ERROR: finding_id is not registered")
            return 1
        if args.json:
            print(json.dumps(record.to_dict(), sort_keys=True))
        else:
            _print_finding_record(record, False)
            print(f"Location: {record.location or 'n/a'}")
            print(f"Validation basis: {record.validation_basis}")
            print(f"Validation reason: {record.validation_reason}")
            print(f"Impact: {record.impact}")
            print(f"Remediation: {record.remediation}")
            print(f"Evidence IDs: {', '.join(record.evidence_ids)}")
            print(f"Source request ID: {record.source.request_id}")
            print(f"Source skill: {record.source.skill}")
            print(f"Source result path: {record.source.result_path}")
        return 0
    except (FindingValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2


def finding_verify(args: argparse.Namespace) -> int:
    try:
        results = verify_all_findings(args.run_dir, args.finding_id)
        ok = all(r.overall_status == "verified" for r in results)
        if args.json:
            print(json.dumps({"verified": ok, "results": [r.to_dict() for r in results]}, sort_keys=True))
        else:
            for r in results:
                print(f"Finding ID: {r.finding_id}")
                print(f"Title: {r.title or 'n/a'}")
                print(f"Source-result status: {r.source_status}")
                print(f"Expected source SHA-256: {r.expected_source_sha256 or 'n/a'}")
                print(f"Actual source SHA-256: {r.actual_source_sha256 or 'n/a'}")
                print(f"Evidence status: {r.evidence_status}")
                print(f"Current-scope status: {r.current_scope_status}")
                print(f"Overall status: {r.overall_status}")
                print(f"Reason: {r.reason}")
        return 0 if ok else 1
    except (FindingValidationError, StateValidationError) as exc:
        print(f"ERROR: {exc}")
        return 2

def _default_corpus_dir() -> str:
    import outrider.benchmark as benchmark_pkg
    return str(Path(benchmark_pkg.__file__).resolve().parent / "ground_truth")


def orchestrate_run(args: argparse.Namespace) -> int:
    if not args.live:
        print("ERROR: live orchestration requires --live and provider safeguard enrollment.")
        print("The governed loop dispatches skills through an external agent runtime;")
        print("re-run with --live once Anthropic Cyber Verification enrollment is in place.")
        return 2
    executor = ClaudeSubprocessExecutor(enabled=True, skills_dir=args.skills_dir, model=args.model)
    seeds = [SeedRequest(
        skill=args.seed_skill, action_type=args.seed_action,
        objective=args.seed_objective, candidate=args.seed_candidate,
    )]
    bounds = OrchestrationBounds(
        max_hops=args.max_hops, max_requests=args.max_requests,
        max_wall_clock_seconds=args.max_seconds,
    )
    try:
        report = run_orchestration(
            args.run_dir, executor=executor, actor=args.actor, seeds=seeds,
            route_skill=args.route_skill, bounds=bounds,
        )
    except (StateValidationError, SkillContractValidationError, ExecutorError) as exc:
        print(f"ERROR: {exc}")
        return 2
    if args.json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        print(f"Stop reason: {report.stop_reason}")
        print(f"Hops: {report.hops}")
        print(f"Requests created: {report.requests_created}")
        print(f"Valid results: {report.results_valid}")
        print(f"Invalid results: {report.results_invalid}")
        print(f"Candidates discovered: {report.candidates_discovered}")
        print(f"Deferred (handoff/blocked): {len(report.deferred)}")
    return 0


def orchestrate_status(args: argparse.Namespace) -> int:
    try:
        status = orchestration_status(args.run_dir)
    except StateValidationError as exc:
        print(f"ERROR: {exc}")
        return 2
    if args.json:
        print(json.dumps(status, sort_keys=True))
    else:
        for key, value in status.items():
            print(f"{key}: {value}")
    return 0


def verify_candidates_cmd(args: argparse.Namespace) -> int:
    try:
        verdicts = verify_candidates(args.run_dir, actor=args.actor)
    except (StateValidationError, VerifierError) as exc:
        print(f"ERROR: {exc}")
        return 2
    summary = verification_summary(args.run_dir)
    if args.json:
        print(json.dumps({"summary": summary, "verdicts": [v.to_dict() for v in verdicts]}, sort_keys=True))
    else:
        print(f"Verdicts: {summary['verdict_count']}")
        for label, count in summary["counts"].items():
            print(f"  {label}: {count}")
        for verdict in verdicts:
            print(f"  - {verdict.subject} [{verdict.verdict}] {verdict.rationale}")
    return 0


def benchmark_run(args: argparse.Namespace) -> int:
    from outrider.benchmark.run import run_benchmark
    from outrider.benchmark.corpus import CorpusError
    import tempfile
    corpus = args.corpus or _default_corpus_dir()
    try:
        if args.work_dir:
            result = run_benchmark(corpus, args.work_dir)
        else:
            with tempfile.TemporaryDirectory() as td:
                result = run_benchmark(corpus, td)
    except CorpusError as exc:
        print(f"ERROR: {exc}")
        return 2
    payload = {"totals": result["totals"]} if args.tally_only else result
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        totals = result["totals"]
        for key, value in totals.items():
            print(f"{key}: {value}")
        if not args.tally_only:
            for case in result["cases"]:
                print(f"  - {case['case_id']}: recall={case['discovered_recall']} coverage={case['finding_candidate_coverage']} promoted={case['promoted_findings']}")
    return 0


def benchmark_analyze(args: argparse.Namespace) -> int:
    from outrider.benchmark.run import analyze_misses
    from outrider.benchmark.corpus import CorpusError
    import tempfile
    corpus = args.corpus or _default_corpus_dir()
    try:
        with tempfile.TemporaryDirectory() as td:
            misses = analyze_misses(corpus, td)
    except CorpusError as exc:
        print(f"ERROR: {exc}")
        return 2
    if args.json:
        print(json.dumps(misses, sort_keys=True))
    else:
        for entry in misses:
            print(f"{entry['case_id']}:")
            print(f"  missing discovered: {entry['missing_discovered'] or 'none'}")
            print(f"  missing finding subjects: {entry['missing_finding_subjects'] or 'none'}")
            print(f"  unexpected discovered: {entry['unexpected_discovered'] or 'none'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="outrider",
        description="Outrider Recon CLI harness for run-folder creation and evidence-backed handoff.",
    )
    parser.add_argument("--version", action="version", version=f"outrider-recon {package_version()}")
    parser.add_argument("--runs-root", default="./runs", help="Runs root for the default local web portal. Defaults to ./runs.")
    parser.add_argument("--host", default="127.0.0.1", choices=sorted(LOOPBACK_WEB_HOSTS), help="Loopback host for the default local web portal.")
    parser.add_argument("--port", type=_valid_web_port, default=8765, help="Loopback port for the default local web portal.")
    parser.add_argument("--no-browser", action="store_true", help="Start the local portal without opening a browser.")
    parser.add_argument("--enable-mcp-enrichment", action="store_true", help="Explicitly enable fixed policy-gated discovery enrichment in the browser.")
    subcommands = parser.add_subparsers(dest="command", required=False)

    init_parser = subcommands.add_parser(
        "init", help="Create a new Outrider run folder."
    )
    init_parser.add_argument(
        "target", help="Target/run name, for example acme.example."
    )
    init_parser.add_argument(
        "--scope",
        action="append",
        help="Authorized in-scope domain or pattern. Repeat for multiple values.",
    )
    init_parser.add_argument(
        "--exclude",
        action="append",
        help="Out-of-scope domain or pattern. Repeat for multiple values.",
    )
    init_parser.add_argument(
        "--output-dir",
        default="runs",
        help="Base output directory. Defaults to ./runs.",
    )
    init_parser.add_argument("--actor", help="Operator creating the run manifest.")
    init_parser.add_argument(
        "--authorization-reference", help="Opaque authorization reference metadata."
    )
    init_parser.set_defaults(func=init_run)

    show_parser = subcommands.add_parser(
        "show", help="Show expected files for a run folder."
    )
    show_parser.add_argument(
        "run_dir", help="Run folder path, for example runs/acme.example."
    )
    show_parser.set_defaults(func=show_run)

    scope_parser = subcommands.add_parser(
        "scope-check", help="Evaluate a candidate against a run folder's scope.yaml."
    )
    scope_parser.add_argument("run_dir", help="Run folder path containing scope.yaml.")
    scope_parser.add_argument(
        "candidate", help="Domain, IP address, or URL to evaluate."
    )
    scope_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the structured scope decision as JSON.",
    )
    scope_parser.set_defaults(func=scope_check)

    state_parser = subcommands.add_parser(
        "state", help="Show or transition durable run workflow state."
    )
    state_sub = state_parser.add_subparsers(dest="state_command", required=True)
    state_show_parser = state_sub.add_parser("show", help="Show durable run state.")
    state_show_parser.add_argument("run_dir")
    state_show_parser.add_argument("--json", action="store_true")
    state_show_parser.set_defaults(func=state_show)
    transition_parser = state_sub.add_parser(
        "transition", help="Append a validated state transition."
    )
    transition_parser.add_argument("run_dir")
    transition_parser.add_argument("new_state")
    transition_parser.add_argument("--actor", required=True)
    transition_parser.add_argument("--reason")
    transition_parser.add_argument("--json", action="store_true")
    transition_parser.set_defaults(func=state_transition)
    bootstrap_parser = state_sub.add_parser(
        "bootstrap", help="Bootstrap state tracking for a legacy run folder."
    )
    bootstrap_parser.add_argument("run_dir")
    bootstrap_parser.add_argument("--target", required=True)
    bootstrap_parser.add_argument("--actor", required=True)
    bootstrap_parser.add_argument("--authorization-reference")
    bootstrap_parser.add_argument("--json", action="store_true")
    bootstrap_parser.set_defaults(func=state_bootstrap)

    approval_parser = subcommands.add_parser(
        "approval", help="Grant, revoke, and list offline human approvals."
    )
    approval_sub = approval_parser.add_subparsers(
        dest="approval_command", required=True
    )
    approval_grant_parser = approval_sub.add_parser(
        "grant", help="Append a time-bounded approval grant."
    )
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
    approval_revoke_parser = approval_sub.add_parser(
        "revoke", help="Append an approval revocation."
    )
    approval_revoke_parser.add_argument("run_dir")
    approval_revoke_parser.add_argument("approval_id")
    approval_revoke_parser.add_argument("--actor", required=True)
    approval_revoke_parser.add_argument("--reason", required=True)
    approval_revoke_parser.add_argument("--json", action="store_true")
    approval_revoke_parser.set_defaults(func=approval_revoke)
    approval_list_parser = approval_sub.add_parser(
        "list", help="List derived approval status."
    )
    approval_list_parser.add_argument("run_dir")
    approval_list_parser.add_argument("--json", action="store_true")
    approval_list_parser.set_defaults(func=approval_list)

    action_parser = subcommands.add_parser(
        "action-check", help="Evaluate an offline action policy decision."
    )
    action_parser.add_argument("run_dir")
    action_parser.add_argument("action_type")
    action_parser.add_argument("--candidate")
    action_parser.add_argument("--json", action="store_true")
    action_parser.set_defaults(func=action_check)

    evidence_parser = subcommands.add_parser(
        "evidence", help="Register, list, and verify local run evidence."
    )
    evidence_sub = evidence_parser.add_subparsers(
        dest="evidence_command", required=True
    )
    evidence_register_parser = evidence_sub.add_parser(
        "register", help="Append an evidence registration record."
    )
    evidence_register_parser.add_argument("run_dir")
    evidence_register_parser.add_argument("relative_path")
    evidence_register_parser.add_argument("--actor", required=True)
    evidence_register_parser.add_argument("--type", dest="artifact_type", required=True)
    evidence_register_parser.add_argument("--media-type")
    evidence_register_parser.add_argument("--source")
    evidence_register_parser.add_argument("--note")
    evidence_register_parser.add_argument("--json", action="store_true")
    evidence_register_parser.set_defaults(func=evidence_register)
    evidence_list_parser = evidence_sub.add_parser(
        "list", help="List registered evidence."
    )
    evidence_list_parser.add_argument("run_dir")
    evidence_list_parser.add_argument("--json", action="store_true")
    evidence_list_parser.set_defaults(func=evidence_list)
    evidence_verify_parser = evidence_sub.add_parser(
        "verify", help="Verify registered evidence artifacts."
    )
    evidence_verify_parser.add_argument("run_dir")
    evidence_verify_parser.add_argument("--evidence-id")
    evidence_verify_parser.add_argument("--json", action="store_true")
    evidence_verify_parser.set_defaults(func=evidence_verify)




    finding_parser = subcommands.add_parser("finding", help="Promote, list, show, and verify human-reviewed findings.")
    finding_sub = finding_parser.add_subparsers(dest="finding_command", required=True)
    finding_promote_parser = finding_sub.add_parser("promote", help="Promote a finding_candidate into a validated_finding.")
    finding_promote_parser.add_argument("run_dir")
    finding_promote_parser.add_argument("result_file")
    finding_promote_parser.add_argument("claim_id")
    finding_promote_parser.add_argument("--actor", required=True)
    finding_promote_parser.add_argument("--title", required=True)
    finding_promote_parser.add_argument("--candidate", required=True)
    finding_promote_parser.add_argument("--severity", required=True)
    finding_promote_parser.add_argument("--confidence", required=True)
    finding_promote_parser.add_argument("--validation-basis", required=True)
    finding_promote_parser.add_argument("--validation-reason", required=True)
    finding_promote_parser.add_argument("--impact", required=True)
    finding_promote_parser.add_argument("--remediation", required=True)
    finding_promote_parser.add_argument("--location")
    finding_promote_parser.add_argument("--notes")
    finding_promote_parser.add_argument("--evidence-id", action="append")
    finding_promote_parser.add_argument("--json", action="store_true")
    finding_promote_parser.set_defaults(func=finding_promote)
    finding_list_parser = finding_sub.add_parser("list", help="List promoted findings.")
    finding_list_parser.add_argument("run_dir")
    finding_list_parser.add_argument("--json", action="store_true")
    finding_list_parser.set_defaults(func=finding_list)
    finding_show_parser = finding_sub.add_parser("show", help="Show a promoted finding.")
    finding_show_parser.add_argument("run_dir")
    finding_show_parser.add_argument("finding_id")
    finding_show_parser.add_argument("--json", action="store_true")
    finding_show_parser.set_defaults(func=finding_show)
    finding_verify_parser = finding_sub.add_parser("verify", help="Verify promoted finding provenance and evidence.")
    finding_verify_parser.add_argument("run_dir")
    finding_verify_parser.add_argument("--finding-id")
    finding_verify_parser.add_argument("--json", action="store_true")
    finding_verify_parser.set_defaults(func=finding_verify)

    web_parser = subcommands.add_parser("web", help="Serve the optional local read-only web review plane.")
    web_sub = web_parser.add_subparsers(dest="web_command", required=True)
    web_serve_parser = web_sub.add_parser("serve", help="Serve run review UI on a loopback interface.")
    web_serve_parser.add_argument("runs_root")
    web_serve_parser.add_argument("--host", default="127.0.0.1", choices=sorted(LOOPBACK_WEB_HOSTS))
    web_serve_parser.add_argument("--port", type=_valid_web_port, default=8765)
    web_serve_parser.add_argument("--enable-mcp-enrichment", action="store_true", help="Explicitly enable five fixed policy-gated MCP enrichment tools in the loopback web UI.")
    web_serve_parser.add_argument("--no-browser", action="store_true", help=argparse.SUPPRESS)
    web_serve_parser.set_defaults(func=web_serve)

    contract_parser = subcommands.add_parser("contract", help="Create and validate skill interchange contracts.")
    contract_sub = contract_parser.add_subparsers(dest="contract_command", required=True)
    contract_req = contract_sub.add_parser("request", help="Skill request contracts.")
    contract_req_sub = contract_req.add_subparsers(dest="request_command", required=True)
    contract_req_create = contract_req_sub.add_parser("create", help="Create a skill request contract.")
    contract_req_create.add_argument("run_dir")
    contract_req_create.add_argument("skill")
    contract_req_create.add_argument("--actor", required=True)
    contract_req_create.add_argument("--objective", required=True)
    contract_req_create.add_argument("--action-type", required=True)
    contract_req_create.add_argument("--candidate")
    contract_req_create.add_argument("--evidence-id", action="append")
    contract_req_create.add_argument("--max-items", type=int, default=100)
    contract_req_create.add_argument("--notes")
    contract_req_create.add_argument("--json", action="store_true")
    contract_req_create.set_defaults(func=contract_request_create)
    contract_req_validate = contract_req_sub.add_parser("validate", help="Validate a skill request contract.")
    contract_req_validate.add_argument("run_dir")
    contract_req_validate.add_argument("request_file")
    contract_req_validate.add_argument("--json", action="store_true")
    contract_req_validate.set_defaults(func=contract_request_validate)
    contract_res = contract_sub.add_parser("result", help="Skill result contracts.")
    contract_res_sub = contract_res.add_subparsers(dest="result_command", required=True)
    contract_res_validate = contract_res_sub.add_parser("validate", help="Validate a skill result contract.")
    contract_res_validate.add_argument("run_dir")
    contract_res_validate.add_argument("result_file")
    contract_res_validate.add_argument("--json", action="store_true")
    contract_res_validate.set_defaults(func=contract_result_validate)

    orchestrate_parser = subcommands.add_parser("orchestrate", help="Drive the governed agent-to-agent loop over a run.")
    orchestrate_sub = orchestrate_parser.add_subparsers(dest="orchestrate_command", required=True)
    orchestrate_run_parser = orchestrate_sub.add_parser("run", help="Run the governed loop (requires --live and provider safeguard enrollment).")
    orchestrate_run_parser.add_argument("run_dir")
    orchestrate_run_parser.add_argument("--actor", required=True)
    orchestrate_run_parser.add_argument("--seed-skill", default="offensive-osint")
    orchestrate_run_parser.add_argument("--seed-action", default="local_analysis")
    orchestrate_run_parser.add_argument("--seed-objective", default="seed governed recon")
    orchestrate_run_parser.add_argument("--seed-candidate", default=None)
    orchestrate_run_parser.add_argument("--route-skill", default="offensive-osint")
    orchestrate_run_parser.add_argument("--max-hops", type=int, default=25)
    orchestrate_run_parser.add_argument("--max-requests", type=int, default=50)
    orchestrate_run_parser.add_argument("--max-seconds", type=float, default=300.0)
    orchestrate_run_parser.add_argument("--live", action="store_true", help="Enable the live agent executor. Off by default.")
    orchestrate_run_parser.add_argument("--model", default="opus")
    orchestrate_run_parser.add_argument("--skills-dir", default=str(Path.home() / ".claude" / "skills"))
    orchestrate_run_parser.add_argument("--json", action="store_true")
    orchestrate_run_parser.set_defaults(func=orchestrate_run)
    orchestrate_status_parser = orchestrate_sub.add_parser("status", help="Show orchestration contract inventory for a run.")
    orchestrate_status_parser.add_argument("run_dir")
    orchestrate_status_parser.add_argument("--json", action="store_true")
    orchestrate_status_parser.set_defaults(func=orchestrate_status)

    verify_parser = subcommands.add_parser("verify", help="Independent advisory verification of finding candidates.")
    verify_sub = verify_parser.add_subparsers(dest="verify_command", required=True)
    verify_candidates_parser = verify_sub.add_parser("candidates", help="Produce advisory verdicts for finding candidates.")
    verify_candidates_parser.add_argument("run_dir")
    verify_candidates_parser.add_argument("--actor", default="verifier")
    verify_candidates_parser.add_argument("--json", action="store_true")
    verify_candidates_parser.set_defaults(func=verify_candidates_cmd)

    benchmark_parser = subcommands.add_parser("benchmark", help="Run the deterministic benchmark harness over the ground-truth corpus.")
    benchmark_sub = benchmark_parser.add_subparsers(dest="benchmark_command", required=True)
    benchmark_run_parser = benchmark_sub.add_parser("run", help="Build, run, judge and tally the corpus with the stub executor.")
    benchmark_run_parser.add_argument("--corpus", default=None, help="Corpus directory. Defaults to the packaged ground_truth corpus.")
    benchmark_run_parser.add_argument("--work-dir", default=None, help="Where to build run folders. Defaults to a temporary directory.")
    benchmark_run_parser.add_argument("--tally-only", action="store_true", help="Print only aggregate totals.")
    benchmark_run_parser.add_argument("--json", action="store_true")
    benchmark_run_parser.set_defaults(func=benchmark_run)
    benchmark_analyze_parser = benchmark_sub.add_parser("analyze-misses", help="Report expected-but-missing candidates per case.")
    benchmark_analyze_parser.add_argument("--corpus", default=None)
    benchmark_analyze_parser.add_argument("--json", action="store_true")
    benchmark_analyze_parser.set_defaults(func=benchmark_analyze)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        return launch_local_portal(args, create_default_root=True)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
