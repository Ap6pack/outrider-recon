# ADR 0009: Web run creation and scope management

## Status

Accepted.

## Context

The local web control plane already uses a process-local control token,
same-origin checks, `Sec-Fetch-Site` rejection, sanitized JSON errors,
UUID-based run resolution, loopback-only serving, and a process-local mutation
lock. The next safe increment is limited to creating an initialized run,
replacing scope rules while that run is still initialized, and evaluating scope
candidates in the browser.

## Decision

Outrider supports guarded atomic web run creation through `POST /api/runs`,
initialized-only scope replacement through `PUT /api/runs/{run_id}/scope`, and
read-only scope candidate evaluation through `POST /api/runs/{run_id}/scope/check`.

Run creation validates the target, actor, authorization reference, and complete
initial scope before creating the final run directory. The server derives an
immediate-child directory name from the normalized target. Domain names use the
lowercase domain, IPv4 addresses use a dotted-address-safe name, and IPv6
addresses use an expanded hyphenated representation without literal colons.
The browser never supplies a directory or path. Symlinked run roots and existing
or symlinked destinations are rejected.

Creation is all-or-nothing: the complete standard run structure is built in a
temporary sibling under the runs root, validated, and atomically renamed to the
final destination. Failures remove temporary data and leave no partial final run.

Scope replacement uses the exact current `scope.yaml` bytes as a lowercase
SHA-256 stale-write precondition. Web scope edits are permitted only while the
workflow state is `initialized`; later states return a conflict. Replacement
updates only `in_scope`, `out_of_scope`, and server-managed `scope_control`
metadata. Other top-level values are preserved, including unknown future fields,
but PyYAML may normalize formatting and comments.

`scope_control` records server-generated attribution, reason, timestamps, a
revision number, append-only web history entries, and the previous exact-file
revision. It does not store the resulting file hash inside the same file. The
actor is operator-supplied attribution, not authenticated identity.

Scope writes use a temporary file in the run directory, flush and fsync that
file, validate it with the authoritative parser, confirm the manifest target
remains allowed, and atomically replace `scope.yaml`. No state event is faked and
`run.jsonl` is not changed.

## Consequences

The mutation lock serializes changes only within this server process. It does
not protect against another Outrider server process, simultaneous CLI mutation,
or direct file edits. Operators must not perform simultaneous CLI and web
mutations against the same run.

The server remains loopback-only, single-operator, unauthenticated, unsuitable
for reverse-proxy exposure, unsuitable for shared-user hosting, and unsupported
for remote hosting. Approval mutations, evidence registration, artifact
transfer, contract mutation, finding promotion, MCP invocation, recon execution,
command execution, report generation, run deletion, and generic action endpoints
remain unsupported in the web control plane.
