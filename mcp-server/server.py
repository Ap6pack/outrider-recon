#!/usr/bin/env python3
"""outrider-recon MCP server -- policy-gated OSINT enrichment tools."""

from __future__ import annotations
from typing import Any, Callable

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    class FastMCP:  # type: ignore[no-redef]
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self._tools: list[Callable[..., Any]] = []
        def tool(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
            def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
                self._tools.append(func); return func
            return decorator
        def run(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("mcp package is required to run the server")

from outrider.mcp_enrichment import mcp_call
import httpx

async def _crtsh_raw(domain: str):
    from outrider.mcp_enrichment import FixedEnrichmentExecutor
    return await FixedEnrichmentExecutor().invoke("crtsh_lookup", {"domain": domain})
async def _hudsonrock_raw(domain: str):
    from outrider.mcp_enrichment import FixedEnrichmentExecutor
    return await FixedEnrichmentExecutor().invoke("hudsonrock_lookup", {"domain": domain})
async def _epss_raw(cve_id: str):
    from outrider.mcp_enrichment import FixedEnrichmentExecutor
    return await FixedEnrichmentExecutor().invoke("epss_score", {"cve_id": cve_id})
async def _wayback_raw(domain: str, limit: int):
    from outrider.mcp_enrichment import FixedEnrichmentExecutor
    return await FixedEnrichmentExecutor().invoke("wayback_urls", {"domain": domain, "limit": limit})
def _dns_records_raw(domain: str):
    from outrider.mcp_enrichment import FixedEnrichmentExecutor
    import asyncio
    return asyncio.run(FixedEnrichmentExecutor().invoke("dns_records", {"domain": domain}))

class _CompatExecutor:
    async def invoke(self, tool, args):
        if tool == "crtsh_lookup": return await _crtsh_raw(args["domain"])
        if tool == "hudsonrock_lookup": return await _hudsonrock_raw(args["domain"])
        if tool == "epss_score": return await _epss_raw(args["cve_id"])
        if tool == "wayback_urls": return await _wayback_raw(args["domain"], args["limit"])
        if tool == "dns_records": return _dns_records_raw(args["domain"])
        raise ValueError("unknown tool")

mcp = FastMCP("outrider-recon", instructions=("Policy-gated OSINT enrichment tools for authorized Outrider runs. Every network or DNS lookup requires an explicit run_dir and an allow decision."))

@mcp.tool()
async def crtsh_lookup(run_dir: str, domain: str) -> dict[str, Any]:
    """Query crt.sh after Outrider policy allows public source lookup for domain."""
    return await mcp_call("crtsh_lookup", run_dir, {"domain": domain}, _CompatExecutor())

@mcp.tool()
async def hudsonrock_lookup(run_dir: str, domain: str) -> dict[str, Any]:
    """Query HudsonRock Cavalier after Outrider policy allows public source lookup."""
    return await mcp_call("hudsonrock_lookup", run_dir, {"domain": domain}, _CompatExecutor())


# ---------------------------------------------------------------------------
# Tool: epss_score
# ---------------------------------------------------------------------------
@mcp.tool()
async def epss_score(run_dir: str, cve_id: str) -> dict[str, Any]:
    """Get EPSS score after Outrider policy allows lookup using manifest target scope."""
    return await mcp_call("epss_score", run_dir, {"cve_id": cve_id}, _CompatExecutor())

@mcp.tool()
async def wayback_urls(run_dir: str, domain: str, limit: int = 100) -> dict[str, Any]:
    """Query Wayback CDX after Outrider policy allows public source lookup."""
    return await mcp_call("wayback_urls", run_dir, {"domain": domain, "limit": limit}, _CompatExecutor())

@mcp.tool()
def dns_records(run_dir: str, domain: str) -> dict[str, Any]:
    """Fetch DNS records only after exact target_enumeration approval allows it."""
    import asyncio
    return asyncio.run(mcp_call("dns_records", run_dir, {"domain": domain}, _CompatExecutor()))

if __name__ == "__main__":
    mcp.run()
