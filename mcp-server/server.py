#!/usr/bin/env python3
"""outrider-recon MCP server -- OSINT recon tools for Claude Code."""
# Copyright (c) 2025 Veritas Aequitas Holdings LLC. All rights reserved.

from __future__ import annotations

import socket
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "outrider-recon",
    instructions=(
        "OSINT reconnaissance tools for domain and vulnerability research. "
        "These complement the outrider-recon skill set with live API queries."
    ),
)

# ---------------------------------------------------------------------------
# Shared HTTP client settings
# ---------------------------------------------------------------------------
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_HEADERS = {"User-Agent": "outrider-recon/1.0 (MCP server; +https://github.com/outrider-recon)"}


async def _get_json(url: str, params: dict[str, Any] | None = None) -> Any:
    """Perform a GET request and return parsed JSON."""
    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Tool: crtsh_lookup
# ---------------------------------------------------------------------------
@mcp.tool()
async def crtsh_lookup(domain: str) -> list[dict[str, Any]]:
    """Query crt.sh certificate transparency logs for a domain.

    Returns certificates issued for the domain including subdomains,
    useful for subdomain enumeration and CA trust analysis.

    Args:
        domain: Target domain (e.g. "example.com")
    """
    try:
        raw = await _get_json("https://crt.sh/", params={"q": domain, "output": "json"})
    except httpx.HTTPStatusError as exc:
        return [{"error": f"crt.sh returned HTTP {exc.response.status_code}"}]
    except httpx.TimeoutException:
        return [{"error": "crt.sh request timed out (30s)"}]
    except Exception as exc:
        return [{"error": f"crt.sh request failed: {exc}"}]

    if not isinstance(raw, list):
        return [{"error": "Unexpected response format from crt.sh"}]

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in raw:
        key = (
            entry.get("common_name", ""),
            entry.get("name_value", ""),
            entry.get("not_before", ""),
        )
        dedup = f"{key}"
        if dedup in seen:
            continue
        seen.add(dedup)
        results.append({
            "common_name": entry.get("common_name"),
            "name_value": entry.get("name_value"),
            "issuer_ca_id": entry.get("issuer_ca_id"),
            "not_before": entry.get("not_before"),
            "not_after": entry.get("not_after"),
        })

    return results


# ---------------------------------------------------------------------------
# Tool: hudsonrock_lookup
# ---------------------------------------------------------------------------
@mcp.tool()
async def hudsonrock_lookup(domain: str) -> dict[str, Any]:
    """Query HudsonRock Cavalier free API for infostealer exposure data.

    Checks whether employees or users of a domain appear in infostealer
    malware logs (credential leaks from compromised machines).

    Args:
        domain: Target domain (e.g. "example.com")
    """
    url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
    try:
        data = await _get_json(url, params={"domain": domain})
    except httpx.HTTPStatusError as exc:
        return {"error": f"HudsonRock returned HTTP {exc.response.status_code}"}
    except httpx.TimeoutException:
        return {"error": "HudsonRock request timed out (30s)"}
    except Exception as exc:
        return {"error": f"HudsonRock request failed: {exc}"}

    stealers: list[str] = []
    for entry in data.get("data", []):
        family = entry.get("stealer_family") or entry.get("stealer")
        if family and family not in stealers:
            stealers.append(family)

    employees = data.get("employees", data.get("data", []))
    users = data.get("users", [])

    return {
        "domain": domain,
        "total": data.get("total", len(data.get("data", []))),
        "employees_count": len(employees) if isinstance(employees, list) else employees,
        "users_count": len(users) if isinstance(users, list) else users,
        "stealer_families": stealers,
    }


# ---------------------------------------------------------------------------
# Tool: epss_score
# ---------------------------------------------------------------------------
@mcp.tool()
async def epss_score(cve_id: str) -> dict[str, Any]:
    """Get EPSS (Exploit Prediction Scoring System) probability for a CVE.

    EPSS estimates the likelihood a vulnerability will be exploited in the
    wild within the next 30 days. Scores range from 0.0 to 1.0.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-3400")
    """
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        return {"error": f"Invalid CVE format: {cve_id!r}. Expected 'CVE-YYYY-NNNNN'."}

    try:
        data = await _get_json("https://api.first.org/data/v1/epss", params={"cve": cve_id})
    except httpx.HTTPStatusError as exc:
        return {"error": f"FIRST EPSS API returned HTTP {exc.response.status_code}"}
    except httpx.TimeoutException:
        return {"error": "FIRST EPSS API request timed out (30s)"}
    except Exception as exc:
        return {"error": f"FIRST EPSS API request failed: {exc}"}

    entries = data.get("data", [])
    if not entries:
        return {"cve": cve_id, "epss": None, "percentile": None, "note": "No EPSS data found"}

    entry = entries[0]
    return {
        "cve": entry.get("cve", cve_id),
        "epss": float(entry["epss"]) if "epss" in entry else None,
        "percentile": float(entry["percentile"]) if "percentile" in entry else None,
    }


# ---------------------------------------------------------------------------
# Tool: wayback_urls
# ---------------------------------------------------------------------------
@mcp.tool()
async def wayback_urls(domain: str, limit: int = 100) -> list[dict[str, str]]:
    """Query the Wayback Machine CDX API for archived URLs of a domain.

    Useful for discovering historical endpoints, forgotten pages, old API
    paths, and content that has been removed from the live site.

    Args:
        domain: Target domain (e.g. "example.com")
        limit: Maximum number of results to return (default 100, max 10000)
    """
    limit = max(1, min(limit, 10000))
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "timestamp,original",
        "limit": str(limit),
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            raw = resp.json()
    except httpx.HTTPStatusError as exc:
        return [{"error": f"Wayback CDX returned HTTP {exc.response.status_code}"}]
    except httpx.TimeoutException:
        return [{"error": "Wayback CDX request timed out (30s)"}]
    except Exception as exc:
        return [{"error": f"Wayback CDX request failed: {exc}"}]

    if not raw or len(raw) < 2:
        return []

    # First row is the header: ["timestamp", "original"]
    results: list[dict[str, str]] = []
    for row in raw[1:]:
        if len(row) >= 2:
            results.append({"timestamp": row[0], "url": row[1]})

    return results


# ---------------------------------------------------------------------------
# Tool: dns_records
# ---------------------------------------------------------------------------
@mcp.tool()
async def dns_records(domain: str) -> dict[str, Any]:
    """Fetch common DNS records for a domain.

    Queries A, AAAA, MX, TXT, NS, SOA, CAA, and CNAME record types.
    Uses system DNS resolver (no external API dependency).

    Args:
        domain: Target domain (e.g. "example.com")
    """
    try:
        import dns.resolver
        _has_dnspython = True
    except ImportError:
        _has_dnspython = False

    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME"]
    results: dict[str, list[str]] = {}

    if _has_dnspython:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 15

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                results[rtype] = [rdata.to_text() for rdata in answers]
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                return {"error": f"Domain {domain!r} does not exist (NXDOMAIN)"}
            except dns.resolver.NoNameservers:
                continue
            except Exception:
                continue
    else:
        # Fallback: socket-only for A/AAAA records
        results["_note"] = [
            "dnspython not installed; only A/AAAA via socket. "
            "Install dnspython for full record type support."
        ]
        try:
            infos = socket.getaddrinfo(domain, None)
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
        except socket.gaierror as exc:
            return {"error": f"DNS lookup failed for {domain!r}: {exc}"}

    return {"domain": domain, "records": results}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="stdio")
