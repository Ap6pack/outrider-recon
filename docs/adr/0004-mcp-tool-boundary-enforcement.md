# ADR 0004: MCP tool-boundary enforcement

## Status

Accepted.

## Context

The optional MCP server exposes five enrichment tools that can initiate HTTP requests or DNS resolution. Outrider already has deterministic local controls for scope, workflow state, approval records, and action-policy decisions. MCP lookups must reuse those controls instead of treating the MCP client as an implicit authorization source.

## Decision

Every exposed MCP lookup now requires an explicit `run_dir` argument. There is no process-global current run, environment fallback, newest-run discovery, or cached decision. Each invocation reloads the current run manifest, workflow state, scope, and approval registry from the supplied run folder.

The MCP boundary uses fixed per-tool mappings:

| MCP tool | Action type | Policy candidate |
| --- | --- | --- |
| `crtsh_lookup` | `public_source_lookup` | supplied domain |
| `hudsonrock_lookup` | `public_source_lookup` | supplied domain |
| `wayback_urls` | `public_source_lookup` | supplied domain |
| `epss_score` | `public_source_lookup` | manifest target |
| `dns_records` | `target_enumeration` | supplied domain |

The caller cannot provide or override an action type. The guard module has no MCP framework dependency and performs no network or DNS behavior. It normalizes domain candidates, rejects URLs, paths, ports, credentials, wildcards, IP addresses, and malformed domains, and then calls the existing `evaluate_action` control layer.

Policy evaluation happens before network activity. A policy error or denial returns a structured MCP response and prevents HTTP client construction, HTTP requests, DNS resolver construction, DNS queries, socket resolution, retries, or fallback resolution.

Allowed calls use the normalized policy candidate for the upstream operation. Passive tools require the candidate to be in current scope and the workflow state to permit `public_source_lookup`. `dns_records` requires the current state and scope to permit `target_enumeration` and an active exact matching approval for the normalized domain. Wildcard scope can place an exact subdomain in scope, but the approval must still match the exact subdomain.

`epss_score` treats the CVE as enrichment input only. Its policy candidate is the manifest target, which must normalize to an in-scope domain in a workflow state that permits `public_source_lookup`. CVE input is validated before the external request.

All MCP tools return a response envelope containing `ok`, `tool`, `policy`, `result`, `error`, and a scope note. Denials use `policy_denied`, run or guard errors use `policy_error`, malformed tool-specific input uses `invalid_input`, and upstream failures are reported only after an allow decision.

MCP discoveries are observations only. Returned domains, URLs, hosts, IPs, certificate names, DNS records, or exposure metadata do not expand `scope.yaml`. MCP responses are transient output and are not automatically registered as evidence.

## Consequences and limitations

- Requiring `run_dir` and returning envelopes is an MCP interface compatibility change.
- Denied or invalid MCP calls produce no network or DNS activity.
- The existing `evaluate_action` policy remains the source of truth for state, scope, approval expiration, and revocation.
- There is no authenticated MCP client identity; approval actor strings remain operator-provided attribution metadata.
- There is no concurrent-writer guarantee beyond the existing local-file controls.
- No intrusive, prohibited, arbitrary-fetch, write, credentialed, or caller-supplied-endpoint MCP tool is introduced.
- Claude skill contract enforcement, automatic evidence capture, finding validation, orchestration, and web UI behavior remain out of scope.
