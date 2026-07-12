from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from outrider.scope import evaluate_scope_path


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
    scope_lines = "\n".join(f"  - {item}" for item in scopes) or "  - TODO"
    exclusion_items = list(exclusions)
    if exclusion_items:
        exclusion_block = "out_of_scope:\n" + "\n".join(f"  - {item}" for item in exclusion_items)
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

    append_jsonl(run_jsonl, {"event": "run_initialized", "target": target, "created_at": utc_now(), "run_dir": str(run_dir)})

    for filename, payload in DEFAULT_FILES.items():
        if write_if_missing(run_dir / filename, json.dumps(payload, indent=2, sort_keys=True) + "\n"):
            created.append(filename)

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
    expected = ["scope.yaml", "run.jsonl", "assets.json", "web_surface.json", "identity_fabric.json", "bb_intel.json", "findings.md", "technique_cards.md", "surface.md", "report.md"]
    print(f"Outrider run: {run_dir}")
    for filename in expected:
        marker = "ok" if (run_dir / filename).exists() else "missing"
        print(f"  [{marker}] {filename}")
    return 0


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="outrider", description="Outrider Recon CLI harness for run-folder creation and evidence-backed handoff.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    init_parser = subcommands.add_parser("init", help="Create a new Outrider run folder.")
    init_parser.add_argument("target", help="Target/run name, for example acme.example.")
    init_parser.add_argument("--scope", action="append", help="Authorized in-scope domain or pattern. Repeat for multiple values.")
    init_parser.add_argument("--exclude", action="append", help="Out-of-scope domain or pattern. Repeat for multiple values.")
    init_parser.add_argument("--output-dir", default="runs", help="Base output directory. Defaults to ./runs.")
    init_parser.set_defaults(func=init_run)

    show_parser = subcommands.add_parser("show", help="Show expected files for a run folder.")
    show_parser.add_argument("run_dir", help="Run folder path, for example runs/acme.example.")
    show_parser.set_defaults(func=show_run)

    scope_parser = subcommands.add_parser("scope-check", help="Evaluate a candidate against a run folder's scope.yaml.")
    scope_parser.add_argument("run_dir", help="Run folder path containing scope.yaml.")
    scope_parser.add_argument("candidate", help="Domain, IP address, or URL to evaluate.")
    scope_parser.add_argument("--json", action="store_true", help="Emit the structured scope decision as JSON.")
    scope_parser.set_defaults(func=scope_check)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
