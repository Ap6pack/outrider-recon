# ADR 0014: Web MCP enrichment controls

## Status

Accepted.

## Context

The local web control plane was intentionally limited to run review and guarded file-backed state changes. The existing MCP companion already exposes five reviewed, policy-gated enrichment tools: `crtsh_lookup`, `hudsonrock_lookup`, `epss_score`, `wayback_urls`, and `dns_records`.

## Decision

Outrider now exposes only that fixed five-tool catalog in the loopback web plane. Browser enrichment is disabled by default and requires `outrider web serve RUNS_ROOT --enable-mcp-enrichment`. The MCP server and web HTTP adapter share `outrider.mcp_enrichment`, preserving MCP tool names and signatures while centralizing fixed tool metadata, strict argument validation, provider calls, response normalization, timeout/error conversion, and policy authorization through `authorize_mcp_tool`.

The web plane adds a network-free preflight and a separate confirmed invocation. Invocation reloads manifest, workflow state, scope, and approvals, compares expected state and revisions, calls `authorize_mcp_tool` immediately before transport, and proceeds only on `allow`. EPSS continues to use the manifest target as the policy candidate; the CVE is validated only as an EPSS lookup argument. DNS remains `target_enumeration` and requires an active exact matching approval.

Providers are fixed in code: crt.sh, HudsonRock Cavalier, FIRST EPSS, Wayback CDX, and DNS. Browser requests cannot supply URLs, hosts, resolvers, methods, headers, credentials, request bodies, timeouts, proxies, approval IDs, or normalized candidates. HTTP uses fixed timeouts, TLS verification, no environment proxy inheritance where supported, no automatic retries, and bounded response bodies. DNS uses a fixed record-type set, bounded resolver behavior, no `ANY`, no zone transfer, no reverse sweep, and no browser-supplied resolver.

Results are bounded and transient: crt.sh 500 entries, HudsonRock 100 stealer families, Wayback 500 web entries, DNS 100 values per type and 500 total, EPSS one entry, 5 MiB upstream HTTP body, and 1 MiB serialized response. The browser can review the response, but no artifact, evidence, contract, finding, report, queue, schedule, background job, cancellation, chaining, recon orchestration, skill execution, shell, subprocess, Claude, or LLM behavior is added.

One web enrichment invocation is serialized per application process. This is process-local protection only; it is not cross-process locking and browser disconnection might not cancel an already-started provider request. Operational logs include only sanitized invocation metadata and omit tokens, authorization references, purpose text, raw arguments, provider responses, DNS records, certificate names, Wayback URLs, headers, cookies, paths, and response bodies.

## Consequences

Fixed MCP enrichment is the first network-enabled web operation because it already has reviewed tool-to-action mappings and policy boundaries. The interface remains loopback-only, single-operator, unauthenticated, unsuitable for reverse proxies, unsuitable for shared hosting, and unsupported for remote deployment. The process-local token is not authentication, actor values are attribution only, provider results do not prove authorization or findings, and returned observations never expand scope automatically.
