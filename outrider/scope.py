from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from pathlib import Path
import re
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml

CandidateType = Literal['domain', 'ip']
DecisionValue = Literal['allow', 'deny', 'error']
RuleSource = Literal['in_scope', 'out_of_scope', 'none']
RuleType = Literal['domain', 'wildcard', 'ip', 'cidr']

class ScopeValidationError(ValueError):
    pass


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ScopeValidationError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping

_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


@dataclass(frozen=True)
class ScopeRule:
    original: str
    kind: RuleType
    value: str | IPv4Address | IPv6Address | IPv4Network | IPv6Network


@dataclass(frozen=True)
class ScopeConfig:
    path: Path
    in_scope: tuple[ScopeRule, ...]
    out_of_scope: tuple[ScopeRule, ...]


@dataclass(frozen=True)
class ScopeDecision:
    original_candidate: str
    normalized_candidate: str | None
    candidate_type: CandidateType | None
    decision: DecisionValue
    matched_rule: str | None
    matched_rule_source: RuleSource
    reason: str

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


_DOMAIN_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')


def load_scope(run_dir: str | Path) -> ScopeConfig:
    path = Path(run_dir) / 'scope.yaml'
    if not path.exists():
        raise ScopeValidationError(f"scope.yaml not found: {path}")
    try:
        data = yaml.load(path.read_text(encoding='utf-8'), Loader=_UniqueKeySafeLoader)
    except ScopeValidationError:
        raise
    except yaml.YAMLError as exc:
        raise ScopeValidationError(f"malformed YAML in {path}: {exc}") from exc
    except OSError as exc:
        raise ScopeValidationError(f"could not read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ScopeValidationError('scope.yaml must contain a top-level mapping')
    if 'in_scope' not in data:
        raise ScopeValidationError('scope.yaml must define in_scope')
    raw_in = data['in_scope']
    if not isinstance(raw_in, list):
        raise ScopeValidationError('in_scope must be a list of strings')
    if not raw_in:
        raise ScopeValidationError('in_scope must not be empty')
    raw_out = data.get('out_of_scope', [])
    if not isinstance(raw_out, list):
        raise ScopeValidationError('out_of_scope must be a list of strings when present')
    if raw_out == ['none']:
        raw_out = []
    in_rules = tuple(_parse_rule(rule, 'in_scope') for rule in raw_in)
    out_rules = tuple(_parse_rule(rule, 'out_of_scope') for rule in raw_out)
    return ScopeConfig(path=path, in_scope=in_rules, out_of_scope=out_rules)


def evaluate_scope(config: ScopeConfig, candidate: str) -> ScopeDecision:
    try:
        normalized, candidate_type, candidate_value = _normalize_candidate(candidate)
    except ScopeValidationError as exc:
        return ScopeDecision(candidate, None, None, 'error', None, 'none', str(exc))
    for rule in config.out_of_scope:
        if _rule_matches(rule, candidate_type, candidate_value):
            return ScopeDecision(
                candidate,
                normalized,
                candidate_type,
                'deny',
                rule.original,
                'out_of_scope',
                'candidate matches out_of_scope rule',
            )
    for rule in config.in_scope:
        if _rule_matches(rule, candidate_type, candidate_value):
            return ScopeDecision(
                candidate,
                normalized,
                candidate_type,
                'allow',
                rule.original,
                'in_scope',
                'candidate matches in_scope rule',
            )
    return ScopeDecision(
        candidate,
        normalized,
        candidate_type,
        'deny',
        None,
        'none',
        'candidate did not match any in_scope rule',
    )


def evaluate_scope_path(run_dir: str | Path, candidate: str) -> ScopeDecision:
    try:
        config = load_scope(run_dir)
    except ScopeValidationError as exc:
        return ScopeDecision(candidate, None, None, 'error', None, 'none', str(exc))
    return evaluate_scope(config, candidate)


def _parse_rule(rule: Any, source: str) -> ScopeRule:
    if not isinstance(rule, str):
        raise ScopeValidationError(f'{source} rules must be strings')
    original = rule
    text = rule.strip().lower()
    if not text:
        raise ScopeValidationError(f'{source} contains an empty rule')
    if '://' in text or '?' in text or '#' in text or '@' in text:
        raise ScopeValidationError(
            f'invalid {source} rule {original!r}: scope rules must be domains, '
            'wildcard domains, IPs, or CIDRs, not URLs or paths'
        )
    if text == '*':
        raise ScopeValidationError(f'invalid {source} rule {original!r}: bare wildcard is not allowed')
    try:
        if '/' in text:
            return ScopeRule(original, 'cidr', ip_network(text, strict=True))
    except ValueError as exc:
        if '/' in text:
            raise ScopeValidationError(f'invalid {source} CIDR rule {original!r}: {exc}') from exc
    try:
        return ScopeRule(original, 'ip', ip_address(text))
    except ValueError:
        if _looks_like_ip_literal(text):
            raise ScopeValidationError(f'invalid {source} IP rule {original!r}')
    if '*' in text:
        if not text.startswith('*.') or text.count('*') != 1:
            raise ScopeValidationError(
                f'invalid {source} wildcard rule {original!r}: '
                'wildcard must be the complete leftmost label'
            )
        apex = text[2:]
        _validate_domain(apex, original, source)
        return ScopeRule(original, 'wildcard', apex)
    if '/' in text or ':' in text:
        raise ScopeValidationError(
            f'invalid {source} rule {original!r}: '
            'domain rules must not contain paths, ports, or credentials'
        )
    _validate_domain(text, original, source)
    return ScopeRule(original, 'domain', text)


def _normalize_candidate(
    candidate: str,
) -> tuple[str, CandidateType, str | IPv4Address | IPv6Address]:
    if not isinstance(candidate, str):
        raise ScopeValidationError('candidate must be a string')
    text = candidate.strip()
    if not text:
        raise ScopeValidationError('candidate must not be empty')
    if '://' in text:
        parsed = urlsplit(text)
        if not parsed.scheme or not parsed.netloc or not parsed.hostname:
            raise ScopeValidationError('candidate URL is malformed')
        if parsed.username is not None or parsed.password is not None:
            raise ScopeValidationError('candidate URL must not contain embedded credentials')
        host = parsed.hostname
        return _normalize_host(host)
    if any(ch in text for ch in '/?#@'):
        raise ScopeValidationError('candidate must be a domain, IP address, or URL')
    if ':' in text and not _can_be_ip(text):
        raise ScopeValidationError(
            'candidate contains a port or malformed IPv6 address; '
            'use a valid URL for host:port values'
        )
    return _normalize_host(text)


def _normalize_host(
    host: str,
) -> tuple[str, CandidateType, str | IPv4Address | IPv6Address]:
    host = host.strip().lower()
    if host.endswith('.'):
        host = host[:-1]
    if not host:
        raise ScopeValidationError('candidate hostname is empty')
    try:
        ip = ip_address(host)
        return str(ip), 'ip', ip
    except ValueError:
        if _looks_like_ip_literal(host):
            raise ScopeValidationError('candidate IP address is malformed')
    _validate_domain(host, host, 'candidate')
    return host, 'domain', host


def _validate_domain(domain: str, original: str, source: str) -> None:
    if len(domain) > 253:
        raise ScopeValidationError(f'invalid {source} domain {original!r}: domain is too long')
    if domain.startswith('.') or domain.endswith('.') or '..' in domain:
        raise ScopeValidationError(f'invalid {source} domain {original!r}')
    labels = domain.split('.')
    if len(labels) < 2:
        raise ScopeValidationError(f'invalid {source} domain {original!r}: expected at least two labels')
    for label in labels:
        if not _DOMAIN_LABEL.fullmatch(label):
            raise ScopeValidationError(f'invalid {source} domain {original!r}')


def _rule_matches(
    rule: ScopeRule,
    candidate_type: CandidateType,
    candidate_value: str | IPv4Address | IPv6Address,
) -> bool:
    if candidate_type == 'ip':
        if rule.kind == 'ip':
            return candidate_value == rule.value
        if rule.kind == 'cidr':
            return candidate_value in rule.value  # type: ignore[operator]
        return False
    if rule.kind == 'domain':
        return candidate_value == rule.value
    if rule.kind == 'wildcard':
        suffix = '.' + str(rule.value)
        return (
            isinstance(candidate_value, str)
            and candidate_value.endswith(suffix)
            and candidate_value != rule.value
        )
    return False


def _looks_like_ip_literal(text: str) -> bool:
    return ':' in text or bool(re.fullmatch(r'[0-9.]+', text))


def _can_be_ip(text: str) -> bool:
    try:
        ip_address(text)
        return True
    except ValueError:
        return False

import hashlib
import os
import tempfile
from datetime import datetime, timezone


def normalize_rule_key(rule: Any, source: str) -> str:
    parsed = _parse_rule(rule, source)
    return f"{parsed.kind}:{parsed.value}"


def normalized_scope_rules(rules: list[Any], source: str) -> list[ScopeRule]:
    return [_parse_rule(rule, source) for rule in rules]


def normalize_target_host(target: str) -> str:
    if not isinstance(target, str):
        raise ScopeValidationError('target must be a string')
    parsed = urlsplit(target.strip()) if '://' in target.strip() else None
    if parsed and any(part == '..' for part in Path(parsed.path).parts):
        raise ScopeValidationError('target URL path must not contain traversal')
    normalized, ctype, _value = _normalize_candidate(target)
    if target.strip().startswith('*.') or '/' in normalized:
        raise ScopeValidationError('target must be a single domain or IP host')
    # reject CIDR and path-like values that _normalize_candidate already rejects
    return normalized


def scope_revision(run_dir: str | Path) -> str:
    return hashlib.sha256((Path(run_dir) / 'scope.yaml').read_bytes()).hexdigest()


def load_scope_document(run_dir: str | Path) -> dict[str, Any]:
    path = Path(run_dir) / 'scope.yaml'
    data = yaml.load(path.read_text(encoding='utf-8'), Loader=_UniqueKeySafeLoader)
    if not isinstance(data, dict):
        raise ScopeValidationError('scope.yaml must contain a top-level mapping')
    return data


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def replace_scope_rules_atomic(run_dir: str | Path, expected_revision: str, actor: str, reason: str, in_scope: list[str], out_of_scope: list[str], target: str) -> str:
    run = Path(run_dir)
    if not expected_revision or scope_revision(run) != expected_revision:
        raise FileExistsError('scope revision is stale')
    if not actor.strip() or not reason.strip():
        raise ScopeValidationError('actor and reason are required')
    in_keys = [normalize_rule_key(r, 'in_scope') for r in in_scope]
    out_keys = [normalize_rule_key(r, 'out_of_scope') for r in out_of_scope]
    if not in_scope or len(in_keys) != len(set(in_keys)) or len(out_keys) != len(set(out_keys)) or set(in_keys) & set(out_keys):
        raise ScopeValidationError('duplicate or conflicting scope rules')
    current = load_scope_document(run)
    current_in = [normalize_rule_key(r, 'in_scope') for r in current.get('in_scope', [])]
    current_out = [normalize_rule_key(r, 'out_of_scope') for r in current.get('out_of_scope', [])]
    if set(current_in) == set(in_keys) and set(current_out) == set(out_keys):
        raise FileExistsError('scope replacement is an effective no-op')
    prior_control = current.get('scope_control') if isinstance(current.get('scope_control'), dict) else None
    history = list(prior_control.get('history', [])) if prior_control else []
    next_rev = int(prior_control.get('revision_number', 0)) + 1 if prior_control else 1
    now = _now_iso()
    history.append({'revision_number': next_rev, 'occurred_at': now, 'actor': actor.strip(), 'reason': reason.strip(), 'previous_revision': expected_revision})
    current['in_scope'] = [r.strip() for r in in_scope]
    current['out_of_scope'] = [r.strip() for r in out_of_scope]
    current['scope_control'] = {'schema_version': 1, 'revision_number': next_rev, 'last_updated_at': now, 'last_updated_by': actor.strip(), 'last_change_reason': reason.strip(), 'history': history}
    content = yaml.safe_dump(current, sort_keys=False, allow_unicode=True)
    fd, tmp = tempfile.mkstemp(prefix='.scope.', suffix='.tmp', dir=run)
    tmp_path = Path(tmp)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(content); handle.flush(); os.fsync(handle.fileno())
        # validate temporary as scope.yaml by loading its text via yaml and parsing rules
        data = yaml.load(tmp_path.read_text(encoding='utf-8'), Loader=_UniqueKeySafeLoader)
        if not isinstance(data, dict): raise ScopeValidationError('scope.yaml must contain a top-level mapping')
        tmp_dir = tempfile.mkdtemp(prefix='.scope-validate-', dir=run)
        try:
            Path(tmp_dir, 'scope.yaml').write_text(content, encoding='utf-8')
            cfg = load_scope(tmp_dir)
            if evaluate_scope(cfg, target).decision != 'allow':
                raise ScopeValidationError('manifest target must remain allowed by scope')
        finally:
            import shutil; shutil.rmtree(tmp_dir, ignore_errors=True)
        os.replace(tmp_path, run / 'scope.yaml')
    finally:
        if tmp_path.exists(): tmp_path.unlink(missing_ok=True)
    return scope_revision(run)
