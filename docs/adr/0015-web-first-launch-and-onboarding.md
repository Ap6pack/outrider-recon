# ADR 0015: Web-first launch and engagement onboarding

## Status

Accepted.

## Context

New operators previously needed to understand run folders, CLI subcommands,
workflow state, scope files, and control-plane terminology before they could
start. The local web control plane already existed, but it was not the normal
entry point.

## Decision

`outrider` with no subcommand is the default human launcher. It starts the
loopback portal with `./runs`, `127.0.0.1`, port `8765`, browser opening enabled,
no authentication, and discovery enrichment disabled unless explicitly requested.
The advanced `outrider web serve RUNS_ROOT` command remains available.

The implicit launcher safely creates the default runs root when missing, refuses
symlinks and non-directories, and never creates or selects an engagement. The
browser opens only after the loopback server is reachable. The URL contains no
control token and no run ID.

The portal presents a beginner Basic mode with welcome, engagement creation,
resume cards, plain-language phase labels, and **Review Scope** as the next
action. **Open Advanced Workspace** exposes the existing technical controls.
This choice is not persisted in browser storage.

Engagement platform and optional traffic-identification header metadata are
stored with existing run metadata in `scope.yaml`. Platform, authorization
reference, operator, and traffic header values are metadata only; they do not
prove authorization, expand scope, or alter policy. Sensitive credential-bearing
headers such as `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
and `X-API-Key` are refused.

## Consequences

Existing CLI-created and older web-created runs remain compatible because the
new metadata is optional and schema versions are unchanged. Onboarding performs
no discovery, no enrichment, no workflow transition, no evidence or artifact
capture, no skill execution, no Claude execution, no queueing, no orchestration,
and no reporting.

The portal remains loopback-only, unauthenticated, single-operator, unsuitable
for reverse-proxy exposure, unsuitable for shared hosting, and unsupported for
remote deployment. The process-local token protects accidental cross-site
mutation; it is not authentication.
