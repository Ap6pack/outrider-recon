#!/usr/bin/env python3
"""outrider-recon MCP server -- policy-gated OSINT enrichment tools."""
# Copyright (c) 2025 Veritas Aequitas Holdings LLC. All rights reserved.

from __future__ import annotations

import re
import socket
from typing import Any, Callable, Awaitable

import httpx

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - exercised through test stubs/import fallback
    class FastMCP:  # type: ignore[no-redef]
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self._tools: list[Callable[..., Any]] = []
        def tool(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
            def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
                self._tools.append(func)
                return func
            return decorator
        def run(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("mcp package is required to run the server")

from outrider.mcp_guard import MCPGuardDecision, authorize_mcp_tool

mcp = FastMCP(
    "outrider-recon",
    instructions=(
        "Policy-gated OSINT enrichment tools for authorized Outrider runs. "
        "Every network or DNS lookup requires an explicit run_dir and an allow decision."
    ),
)

_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_HEADERS = {"User-Agent": "outrider-recon/1.0 (MCP server; +https://github.com/outrider-recon)"}
_SCOPE_NOTE = "Returned observations do not expand authorized scope."
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _envelope(tool: str, policy: MCPGuardDecision, result: Any = None, error: dict[str, str] | None = None) -> dict[str, Any]:
    return {"ok": error is None, "tool": tool, "policy": policy.to_dict(), "result": result if error is None else None, "error": error, "scope_note": _SCOPE_NOTE}


def _policy_block(tool: str, policy: MCPGuardDecision) -> dict[str, Any]:
    code = "policy_denied" if policy.decision == "deny" else "policy_error"
    return _envelope(tool, policy, error={"code": code, "message": policy.reason})


def _invalid(tool: str, policy: MCPGuardDecision, message: str) -> dict[str, Any]:
    return _envelope(tool, policy, error={"code": "invalid_input", "message": message})


def _upstream(tool: str, policy: MCPGuardDecision, code: str, message: str) -> dict[str, Any]:
    return _envelope(tool, policy, error={"code": code, "message": message})


async def _get_json(url: str, params: dict[str, Any] | None = None) -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()


async def _crtsh_raw(domain: str) -> list[dict[str, Any]]:
    raw = await _get_json("https://crt.sh/", params={"q": domain, "output": "json"})
    if not isinstance(raw, list):
        raise ValueError("Unexpected response format from crt.sh")
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("Unexpected response format from crt.sh")
        key = (entry.get("common_name", ""), entry.get("name_value", ""), entry.get("not_before", ""))
        dedup = f"{key}"
        if dedup in seen:
            continue
        seen.add(dedup)
        results.append({"common_name": entry.get("common_name"), "name_value": entry.get("name_value"), "issuer_ca_id": entry.get("issuer_ca_id"), "not_before": entry.get("not_before"), "not_after": entry.get("not_after")})
    return results


async def _hudsonrock_raw(domain: str) -> dict[str, Any]:
    data = await _get_json("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain", params={"domain": domain})
    if not isinstance(data, dict):
        raise ValueError("Unexpected response format from HudsonRock")
    stealers: list[str] = []
    for entry in data.get("data", []):
        if isinstance(entry, dict):
            family = entry.get("stealer_family") or entry.get("stealer")
            if family and family not in stealers:
                stealers.append(family)
    employees = data.get("employees", data.get("data", []))
    users = data.get("users", [])
    return {"domain": domain, "total": data.get("total", len(data.get("data", []))), "employees_count": len(employees) if isinstance(employees, list) else employees, "users_count": len(users) if isinstance(users, list) else users, "stealer_families": stealers}


async def _epss_raw(cve_id: str) -> dict[str, Any]:
    data = await _get_json("https://api.first.org/data/v1/epss", params={"cve": cve_id})
    if not isinstance(data, dict):
        raise ValueError("Unexpected response format from FIRST EPSS")
    entries = data.get("data", [])
    if not entries:
        return {"cve": cve_id, "epss": None, "percentile": None, "note": "No EPSS data found"}
    entry = entries[0]
    if not isinstance(entry, dict):
        raise ValueError("Unexpected response format from FIRST EPSS")
    return {"cve": entry.get("cve", cve_id), "epss": float(entry["epss"]) if "epss" in entry else None, "percentile": float(entry["percentile"]) if "percentile" in entry else None}


async def _wayback_raw(domain: str, limit: int) -> list[dict[str, str]]:
    raw = await _get_json("https://web.archive.org/cdx/search/cdx", params={"url": f"{domain}/*", "output": "json", "fl": "timestamp,original", "limit": str(limit)})
    if not isinstance(raw, list):
        raise ValueError("Unexpected response format from Wayback CDX")
    if len(raw) < 2:
        return []
    results: list[dict[str, str]] = []
    for row in raw[1:]:
        if not isinstance(row, list):
            raise ValueError("Unexpected response format from Wayback CDX")
        if len(row) >= 2:
            results.append({"timestamp": row[0], "url": row[1]})
    return results


def _dns_records_raw(domain: str) -> dict[str, Any]:
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME"]
    results: dict[str, list[str]] = {}
    try:
        import dns.resolver  # type: ignore[import-not-found]
        has_dnspython = True
    except ImportError:
        has_dnspython = False

    if has_dnspython:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 15
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                results[rtype] = [rdata.to_text() for rdata in answers]
            except dns.resolver.NXDOMAIN:
                return {"error": f"Domain {domain!r} does not exist (NXDOMAIN)"}
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
                continue
    else:
        results["_note"] = ["dnspython not installed; only A/AAAA via socket. Install dnspython for full record type support."]
        try:
            infos = socket.getaddrinfo(domain, None)
        except socket.gaierror as exc:
            return {"error": f"DNS lookup failed: {exc}"}
        a_records: list[str] = []
        aaaa_records: list[str] = []
        for info in infos:
            family, _, _, _, sockaddr = info
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in a_records:
                a_records.append(addr)
            elif family == socket.AF_INET6 and addr not in aaaa_records:
                aaaa_records.append(addr)
        if a_records:
            results["A"] = a_records
        if aaaa_records:
            results["AAAA"] = aaaa_records
    return {"domain": domain, "records": results}


async def _run_http_tool(tool: str, run_dir: str, helper: Callable[[str], Awaitable[Any]], domain: str) -> dict[str, Any]:
    policy = authorize_mcp_tool(tool, run_dir, domain=domain)
    if policy.decision != "allow":
        return _policy_block(tool, policy)
    normalized = policy.normalized_policy_candidate or ""
    try:
        return _envelope(tool, policy, await helper(normalized))
    except httpx.TimeoutException:
        return _upstream(tool, policy, "upstream_timeout", f"{tool} request timed out")
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        return _upstream(tool, policy, "upstream_http_error", f"{tool} returned HTTP {status}")
    except ValueError as exc:
        return _upstream(tool, policy, "unexpected_response", str(exc))
    except Exception:
        return _upstream(tool, policy, "upstream_error", f"{tool} request failed")


@mcp.tool()
async def crtsh_lookup(run_dir: str, domain: str) -> dict[str, Any]:
    """Query crt.sh after Outrider policy allows public source lookup for domain."""
    return await _run_http_tool("crtsh_lookup", run_dir, _crtsh_raw, domain)


@mcp.tool()
async def hudsonrock_lookup(run_dir: str, domain: str) -> dict[str, Any]:
    """Query HudsonRock Cavalier after Outrider policy allows public source lookup."""
    return await _run_http_tool("hudsonrock_lookup", run_dir, _hudsonrock_raw, domain)


@mcp.tool()
async def epss_score(run_dir: str, cve_id: str) -> dict[str, Any]:
    """Get EPSS score after Outrider policy allows lookup using manifest target scope."""
    policy = authorize_mcp_tool("epss_score", run_dir)
    if policy.decision != "allow":
        return _policy_block("epss_score", policy)
    if not isinstance(cve_id, str):
        return _invalid("epss_score", policy, "cve_id must be a string")
    cve = cve_id.strip().upper()
    if not _CVE.fullmatch(cve):
        return _invalid("epss_score", policy, "Invalid CVE format. Expected CVE-YYYY-NNNN with at least four numeric digits.")
    try:
        return _envelope("epss_score", policy, await _epss_raw(cve))
    except httpx.TimeoutException:
        return _upstream("epss_score", policy, "upstream_timeout", "FIRST EPSS API request timed out")
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        return _upstream("epss_score", policy, "upstream_http_error", f"FIRST EPSS API returned HTTP {status}")
    except ValueError as exc:
        return _upstream("epss_score", policy, "unexpected_response", str(exc))
    except Exception:
        return _upstream("epss_score", policy, "upstream_error", "FIRST EPSS API request failed")


@mcp.tool()
async def wayback_urls(run_dir: str, domain: str, limit: int = 100) -> dict[str, Any]:
    """Query Wayback CDX after Outrider policy allows public source lookup."""
    policy = authorize_mcp_tool("wayback_urls", run_dir, domain=domain)
    if policy.decision != "allow":
        return _policy_block("wayback_urls", policy)
    if type(limit) is not int:
        return _invalid("wayback_urls", policy, "limit must be an integer")
    if limit < 1 or limit > 10000:
        return _invalid("wayback_urls", policy, "limit must be between 1 and 10000")
    try:
        return _envelope("wayback_urls", policy, await _wayback_raw(policy.normalized_policy_candidate or "", limit))
    except httpx.TimeoutException:
        return _upstream("wayback_urls", policy, "upstream_timeout", "Wayback CDX request timed out")
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        return _upstream("wayback_urls", policy, "upstream_http_error", f"Wayback CDX returned HTTP {status}")
    except ValueError as exc:
        return _upstream("wayback_urls", policy, "unexpected_response", str(exc))
    except Exception:
        return _upstream("wayback_urls", policy, "upstream_error", "Wayback CDX request failed")


@mcp.tool()
def dns_records(run_dir: str, domain: str) -> dict[str, Any]:
    """Fetch DNS records only after exact target_enumeration approval allows it."""
    policy = authorize_mcp_tool("dns_records", run_dir, domain=domain)
    if policy.decision != "allow":
        return _policy_block("dns_records", policy)
    try:
        raw = _dns_records_raw(policy.normalized_policy_candidate or "")
    except Exception:
        return _upstream("dns_records", policy, "upstream_error", "DNS lookup failed")
    if isinstance(raw, dict) and "error" in raw:
        return _upstream("dns_records", policy, "upstream_error", str(raw["error"]))
    return _envelope("dns_records", policy, raw)


if __name__ == "__main__":
    mcp.run(transport="stdio")
