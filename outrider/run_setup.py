from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import json, os, shutil, tempfile
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit
import re

import yaml

from outrider.state import initialize_state, load_manifest, load_state
from outrider.scope import ScopeValidationError, evaluate_scope, load_scope, normalize_rule_key, normalized_scope_rules, normalize_target_host, scope_revision

DEFAULT_FILES = {
    "assets.json": {"assets": [], "notes": "Discovered assets will be stored here."},
    "web_surface.json": {"hosts": [], "apis": [], "interesting_paths": [], "notes": "Web and API surface observations will be stored here."},
    "identity_fabric.json": {"providers": [], "tenants": [], "domains": [], "notes": "Identity, federation, and SaaS observations will be stored here."},
    "bb_intel.json": {"matches": [], "notes": "Public disclosure intelligence matches will be stored here."},
}
EXPECTED_ENTRIES = ["manifest.json","scope.yaml","run.jsonl","evidence.jsonl","approvals.jsonl","findings.jsonl","artifacts","contracts","contracts/requests","contracts/results","assets.json","web_surface.json","identity_fabric.json","bb_intel.json","findings.md","technique_cards.md","surface.md","report.md"]

class RunSetupError(ValueError): pass
class RunConflictError(RunSetupError): pass

@dataclass(frozen=True)
class WebRunRequest:
    target: str
    actor: str
    authorization_reference: str
    in_scope: list[str]
    out_of_scope: list[str]
    engagement_platform: str | None = None
    traffic_header: dict[str, str] | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def render_scope_yaml(target: str, scopes: Iterable[str], exclusions: Iterable[str], *, scope_control: dict[str, Any] | None = None, engagement_platform: str | None = None, traffic_header: dict[str, str] | None = None) -> str:
    if scope_control is None:
        scope_lines = "\n".join(f"  - {json.dumps(item)}" for item in scopes) or "  - TODO"
        exclusion_items = list(exclusions)
        if exclusion_items:
            exclusion_block = "out_of_scope:\n" + "\n".join(f"  - {json.dumps(item)}" for item in exclusion_items)
        else:
            exclusion_block = "out_of_scope: []"
        platform_line = f"engagement_platform: {json.dumps(engagement_platform)}\n" if engagement_platform else ""
        headers = ""
        if traffic_header:
            headers = "  headers:\n" + "\n".join(f"    {json.dumps(k)}: {json.dumps(v)}" for k, v in traffic_header.items()) + "\n"
        return f"""target: {target}
created_at: {utc_now()}
engagement_type: authorized_external_recon
{platform_line}boundary:
  - read_only_recon_by_default
  - explicit_rules_of_engagement_required_for_post_discovery
  - no_destructive_validation_without_written_authorization
in_scope:
{scope_lines}
{exclusion_block}
traffic_tagging:
  user_agent: TODO
  source_ip: TODO
{headers}notes:
  - Replace TODO values before using this run folder for real work.
"""
    data: dict[str, Any] = {
        "target": target,
        "created_at": utc_now(),
        "engagement_type": "authorized_external_recon",
        "boundary": ["read_only_recon_by_default", "explicit_rules_of_engagement_required_for_post_discovery", "no_destructive_validation_without_written_authorization"],
        "in_scope": list(scopes),
        "out_of_scope": list(exclusions),
        "traffic_tagging": {"user_agent": "TODO", "source_ip": "TODO"},
        "notes": ["Replace TODO values before using this run folder for real work."],
        "scope_control": scope_control,
    }
    if engagement_platform:
        data["engagement_platform"] = engagement_platform
    if traffic_header:
        data["traffic_tagging"]["headers"] = traffic_header
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)

def render_findings_md(target: str) -> str: return f"# Finding Cards — {target}\n\nThis file is the operator-facing finding card output for the run.\n"
def render_technique_cards_md(target: str) -> str: return f"# Technique Cards — {target}\n\nTechnique cards map discovered surface area to known public disclosure patterns.\n"
def render_surface_md(target: str) -> str: return f"# Ranked Surface — {target}\n\n## P1 — investigate first\n\n_No P1 leads recorded yet._\n"
def render_report_md(target: str) -> str: return f"# Outrider Recon Report — {target}\n\n## Executive summary\n\nTODO: Summarize the highest-value recon leads.\n"

def safe_run_dir_name(normalized_target: str) -> str:
    try:
        ip = ip_address(normalized_target)
        if ip.version == 4:
            return "ipv4-" + str(ip).replace('.', '-')
        return "ipv6-" + ip.exploded.replace(':', '-')
    except ValueError:
        pass
    name = normalized_target.lower()
    if any(c in name for c in '/\\') or name in {'.','..'} or '..' in Path(name).parts:
        raise RunSetupError("target cannot derive a safe run directory")
    return name

def validate_scope_lists(in_scope: Any, out_of_scope: Any) -> tuple[list[str], list[str]]:
    if not isinstance(in_scope, list) or not in_scope:
        raise RunSetupError("in_scope must be a non-empty list")
    if not isinstance(out_of_scope, list):
        raise RunSetupError("out_of_scope must be a list")
    normalized_scope_rules(in_scope, "in_scope"); normalized_scope_rules(out_of_scope, "out_of_scope")
    in_keys=[normalize_rule_key(r,"in_scope") for r in in_scope]; out_keys=[normalize_rule_key(r,"out_of_scope") for r in out_of_scope]
    if len(in_keys)!=len(set(in_keys)): raise RunSetupError("duplicate in_scope rule")
    if len(out_keys)!=len(set(out_keys)): raise RunSetupError("duplicate out_of_scope rule")
    if set(in_keys)&set(out_keys): raise RunSetupError("identical rule appears in both scope lists")
    return [r.strip() for r in in_scope], [r.strip() for r in out_of_scope]

def _ensure_root(root: Path) -> Path:
    if root.is_symlink(): raise RunSetupError("runs root must not be a symlink")
    if not root.exists() or not root.is_dir(): raise RunSetupError("runs root must be an existing directory")
    return root.resolve(strict=True)

def _write_text(path: Path, text: str): path.write_text(text, encoding='utf-8')
def _write_json(path: Path, payload: Any): path.write_text(json.dumps(payload, indent=2, sort_keys=True)+"\n", encoding='utf-8')

def create_standard_run_structure(run_dir: Path, target: str, actor: str, auth_ref: str, in_scope: list[str], out_scope: list[str], *, web_scope_control: bool=False, engagement_platform: str | None = None, traffic_header: dict[str, str] | None = None) -> None:
    run_dir.mkdir(parents=True, exist_ok=False)
    control = None
    if web_scope_control:
        now = utc_now(); control={"schema_version":1,"revision_number":1,"last_updated_at":now,"last_updated_by":actor,"last_change_reason":"Initial web run creation","history":[{"revision_number":1,"occurred_at":now,"actor":actor,"reason":"Initial web run creation","previous_revision":None}]}
    _write_text(run_dir/'scope.yaml', render_scope_yaml(target, in_scope, out_scope, scope_control=control, engagement_platform=engagement_platform, traffic_header=traffic_header))
    (run_dir/'run.jsonl').touch(); initialize_state(run_dir, target, actor, auth_ref)
    for fn,p in DEFAULT_FILES.items(): _write_json(run_dir/fn,p)
    for fn in ['evidence.jsonl','approvals.jsonl','findings.jsonl']: (run_dir/fn).touch()
    (run_dir/'artifacts').mkdir(); (run_dir/'contracts'/'requests').mkdir(parents=True); (run_dir/'contracts'/'results').mkdir(parents=True)
    for fn,txt in {'findings.md':render_findings_md(target),'technique_cards.md':render_technique_cards_md(target),'surface.md':render_surface_md(target),'report.md':render_report_md(target)}.items(): _write_text(run_dir/fn,txt)

def validate_completed_run(run_dir: Path, target: str) -> None:
    manifest=load_manifest(run_dir); state=load_state(run_dir); scope=load_scope(run_dir)
    if manifest.target != target or state.current_state != 'initialized': raise RunSetupError('created run validation failed')
    if evaluate_scope(scope, target).decision != 'allow': raise RunSetupError('target is not allowed by scope')
    for rel in EXPECTED_ENTRIES:
        if not (run_dir/rel).exists(): raise RunSetupError('created run structure is incomplete')

PLATFORM_OPTIONS = ("HackerOne", "Bugcrowd", "Internal assessment", "Client engagement", "Other")
SENSITIVE_TRAFFIC_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
_HEADER_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

def _single_line(value: str, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RunSetupError(f"{field} must be a non-empty string")
    if len(value) > limit or any(ch in value for ch in "\0\r\n"):
        raise RunSetupError(f"{field} is invalid")
    return value.strip()

def validate_engagement_metadata(platform: Any = None, traffic_header: Any = None) -> tuple[str | None, dict[str, str] | None]:
    clean_platform = None
    if platform is not None:
        clean_platform = _single_line(platform, "engagement_platform", 100)
        if clean_platform not in PLATFORM_OPTIONS:
            raise RunSetupError("engagement_platform is not supported")
    if traffic_header in (None, {}):
        return clean_platform, None
    if not isinstance(traffic_header, dict) or set(traffic_header) != {"name", "value"}:
        raise RunSetupError("traffic_header requires name and value")
    name = _single_line(traffic_header.get("name"), "traffic_header.name", 100)
    value = _single_line(traffic_header.get("value"), "traffic_header.value", 500)
    if not _HEADER_RE.match(name) or name.lower() in SENSITIVE_TRAFFIC_HEADERS:
        raise RunSetupError("Store only program traffic-identification metadata here, not credentials, cookies, API keys, or authorization tokens.")
    return clean_platform, {name: value}

def create_web_run_atomic(root: str|Path, req: WebRunRequest) -> Path:
    target=normalize_target_host(req.target); in_s,out_s=validate_scope_lists(req.in_scope, req.out_of_scope)
    platform, traffic_header = validate_engagement_metadata(req.engagement_platform, req.traffic_header)
    tmp_parent=_ensure_root(Path(root)); final=(tmp_parent/safe_run_dir_name(target))
    if final.exists() or final.is_symlink(): raise RunConflictError('run destination already exists')
    # validate target under temp scope
    probe=tempfile.mkdtemp(prefix='.outrider-probe-', dir=tmp_parent)
    shutil.rmtree(probe)
    tmp=Path(tempfile.mkdtemp(prefix='.outrider-create-', dir=tmp_parent))
    try:
        shutil.rmtree(tmp); create_standard_run_structure(tmp, target, req.actor.strip(), req.authorization_reference.strip(), in_s, out_s, web_scope_control=True, engagement_platform=platform, traffic_header=traffic_header)
        validate_completed_run(tmp,target)
        os.replace(tmp, final)
        return final
    except FileExistsError as exc:
        raise RunConflictError('run destination already exists') from exc
    except ScopeValidationError as exc:
        raise RunSetupError(str(exc)) from exc
    finally:
        if tmp.exists(): shutil.rmtree(tmp, ignore_errors=True)
