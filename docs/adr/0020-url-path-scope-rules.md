# ADR 0020: URL/path scope rules

## Context

Bug-bounty programs commonly scope by URL and path — `https://www.example.com/book/`, `/account/cashback`, sometimes with a specific port or scheme — not just by host. Outrider's governed scope engine (`outrider/scope.py`) originally accepted only `domain`, `wildcard`, `ip`, and `cidr` rules and reduced every candidate to a host. URL-scoped programs could not be represented: importing or typing a URL rule failed (`scope rules must be domains … not URLs`), and reducing a scoped URL to its host over-authorized the engagement (`www.example.com` instead of just `/book/`). Operators were forced to hand-edit scope per engagement. The goal is to solve this once, generally, rather than patch each engagement.

## Decision

A new rule kind `url` = `(scheme?, host, port?, path?)` is added to the scope engine as a first-class citizen alongside the existing kinds.

- **Parsing.** A rule is a `url` rule when it carries a scheme (`http`/`https` only), a `/path`, or a `:port` on a host. The host is a concrete domain (a wildcard host stays the existing `wildcard` kind); CIDR notation still parses as `cidr`. Ports are validated to 1–65535. Query strings, fragments, embedded credentials (`?`, `#`, `@`), and non-http(s) schemes are rejected. Paths are lowercased and normalized (leading `/`, collapsed `//`) — case-insensitive matching is looser and therefore safer for an authorization boundary.
- **Reachability.** A bare host that is the host of some `url` rule is in scope for recon/reachability. This lets the manifest target (always a single host) remain in scope even when the authorized surface is path-scoped.
- **Enforcement.** A URL candidate is matched by host, then by scheme (if the rule pins one), port (explicit or scheme-default 80/443, if the rule pins one), and path. Path matching is a directory-prefix match (`/book` and `/book/` both cover `/book/x`); a `*` in a rule path matches exactly one path segment (`/api/*/admin`). Host-level rules (`domain`/`wildcard`/`ip`/`cidr`) continue to match a URL candidate by host/IP with the path ignored.
- **Precedence unchanged.** `out_of_scope` is still evaluated before `in_scope`. A path-specific exclusion does not deny a pathless (bare-host) candidate, so host reachability is preserved while specific paths are carved out.
- **Candidate identity unchanged.** A URL candidate still reduces to its host for identity and reporting, so approvals, skill-contract requests, and MCP-guard policy continue to key on the host; the scheme/port/path are retained only for scope enforcement. Scheme-less `host/path` and `host:port` candidates remain rejected (a full URL is required for path-scoped checks). The manifest target stays a single host: a URL target reduces to its host, and CIDR/port/path/wildcard targets are rejected.
- **Finding schema.** `candidate_type` in `finding-v1.schema.json` (both the contract copy and the packaged copy, kept byte-identical) now permits `url` in addition to `domain` and `ip`; `schema_version` stays 1 (additive).

## Consequences and limitations

Operators can now express URL/path/host:port/scheme scope directly, and the `targets/ → runs/` import preserves the exact path scope from a `memory.md` `In-Scope Assets` table instead of over-authorizing to the host. The change is additive: existing domain/wildcard/ip/cidr rules and host candidates behave exactly as before. Because path matching is a case-insensitive directory-prefix (with single-segment `*`), it is intentionally permissive within an authorized path subtree rather than an exact-URL allowlist; operators who need finer exclusions add `out_of_scope` path rules. The engine reasons purely over the scope document and the candidate string — it performs no network resolution — so it authorizes structurally and does not verify that a host actually serves a given path.
