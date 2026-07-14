# Outrider MCP server

The optional Outrider MCP server exposes five bounded enrichment tools for authorized runs. Every tool that can initiate HTTP or DNS activity is gated by Outrider's local run policy before the request occurs.

## Installation

Install the MCP companion from the repository so the local Outrider package and MCP-only dependencies are available together:

```bash
python -m pip install -r mcp-server/requirements.txt
```

`mcp-server/requirements.txt` installs:

- the local Outrider package (`-e ..`);
- `mcp` for the MCP server framework;
- `httpx` for the fixed HTTP lookups.

`dnspython` is optional. If it is absent, `dns_records` may use the existing bounded socket fallback after policy allows the call.

## Required run context

Every MCP tool requires an explicit `run_dir: str`. There is no default run directory, environment fallback, newest-run discovery, global current run, or cached authorization decision. Each invocation reloads the supplied run folder's current control files.

Example calls:

```python
crtsh_lookup(
    run_dir="runs/example.com",
    domain="example.com",
)
```

```python
dns_records(
    run_dir="runs/example.com",
    domain="api.example.com",
)
```

## Fixed policy mapping

Callers cannot provide `action_type`, `skip_policy`, or `unsafe` arguments. The server maps each tool to a fixed action type:

| Tool | Action type | Policy candidate | Approval requirement |
| --- | --- | --- | --- |
| `crtsh_lookup` | `public_source_lookup` | supplied domain | none under the current action policy |
| `hudsonrock_lookup` | `public_source_lookup` | supplied domain | none under the current action policy |
| `wayback_urls` | `public_source_lookup` | supplied domain | none under the current action policy |
| `epss_score` | `public_source_lookup` | `manifest.json` target | none under the current action policy |
| `dns_records` | `target_enumeration` | supplied domain | active exact matching approval required |

No current MCP tool maps to intrusive or prohibited action categories.

## Workflow and scope requirements

Passive public-source tools require a valid run, a current workflow state that permits `public_source_lookup`, and an in-scope normalized domain candidate. `epss_score` uses the manifest target as that scope candidate; the CVE identifier is only enrichment input.

`dns_records` requires a valid run, a workflow state that permits `target_enumeration`, an in-scope exact normalized domain, and an active exact matching `target_enumeration` approval.

Create the required DNS approval through the existing CLI before calling `dns_records`:

```bash
outrider approval grant \
  runs/example.com \
  target_enumeration \
  api.example.com \
  --actor authorized-operator \
  --reason "Approved bounded DNS enumeration" \
  --duration-minutes 60
```

Approvals for another action type, parent domain, subdomain, IP address, expired grant, or revoked grant do not authorize DNS resolution.

## Response envelope

Every tool returns the same envelope shape:

```json
{
  "ok": true,
  "tool": "crtsh_lookup",
  "policy": {
    "decision": "allow"
  },
  "result": [],
  "error": null,
  "scope_note": "Returned observations do not expand authorized scope."
}
```

Policy denial example:

```json
{
  "ok": false,
  "tool": "dns_records",
  "policy": {
    "decision": "deny"
  },
  "result": null,
  "error": {
    "code": "policy_denied",
    "message": "no active exact matching approval"
  },
  "scope_note": "Returned observations do not expand authorized scope."
}
```

Error codes include `policy_denied`, `policy_error`, `invalid_input`, `upstream_http_error`, `upstream_timeout`, `upstream_error`, and `unexpected_response`.

## No bypass and no automatic side effects

The MCP server does not reimplement scope, state, expiration, revocation, or approval matching. It delegates policy decisions to Outrider's existing Python control layer and refuses denied or invalid calls before network or DNS activity.

Returned certificate names, URLs, domains, DNS records, hosts, IPs, and exposure metadata are observations only. They do not expand authorized scope. MCP output is transient and is not automatically written to artifacts, registered as evidence, appended to workflow state, or added to approval records. Operators may explicitly save useful output and register it later through the evidence CLI.

## Actor and approval limitations

The MCP server does not authenticate callers and does not infer authorization from MCP client identity, run state, or authorization references. Approval actor fields are operator-supplied attribution metadata, not authenticated identities or digital signatures.

## Shared enrichment implementation

The MCP server remains a thin adapter exposing `crtsh_lookup`, `hudsonrock_lookup`, `epss_score`, `wayback_urls`, and `dns_records` with their existing signatures. Provider logic and bounds are shared with the web control plane through `outrider.mcp_enrichment`; every call still requires explicit `run_dir` and current policy authorization.
