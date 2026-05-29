# outrider-recon MCP Server

Optional MCP (Model Context Protocol) companion server for the outrider-recon skills. Provides live OSINT API queries that complement the static skill instructions.

> **Note:** The outrider-recon skills work without this server. The MCP server adds real-time API lookups that skills alone cannot perform.

## Install

```bash
cd mcp-server
pip install -r requirements.txt
```

For full DNS record support (all record types), also install dnspython:

```bash
pip install dnspython
```

## Configure

Add to your `.claude/settings.json` (or use the project `.mcp.json` which is auto-detected):

```json
{
  "mcpServers": {
    "outrider-recon": {
      "type": "stdio",
      "command": "python3",
      "args": ["mcp-server/server.py"]
    }
  }
}
```

## Available Tools

| Tool | Description | Input |
|---|---|---|
| `crtsh_lookup` | Query crt.sh certificate transparency logs | `domain` (string) |
| `hudsonrock_lookup` | Query HudsonRock Cavalier API for infostealer exposure | `domain` (string) |
| `epss_score` | Get EPSS exploitation probability for a CVE | `cve_id` (string, e.g. "CVE-2024-3400") |
| `wayback_urls` | Query Wayback Machine CDX for archived URLs | `domain` (string), `limit` (int, default 100) |
| `dns_records` | Fetch A, AAAA, MX, TXT, NS, SOA, CAA, CNAME records | `domain` (string) |

## Architecture

- **Transport:** stdio (standard for Claude Code MCP servers)
- **Dependencies:** mcp, httpx (minimal footprint)
- **Error handling:** All tools return structured error objects on timeout or HTTP failure
