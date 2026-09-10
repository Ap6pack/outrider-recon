# ADR 0022: Self-healing orchestration

## Context

The operator's goal is that a human only *sets up* an engagement; the governed
loop (ADR 0017) then runs unattended. Phase 1 (ADR 0021) let it enumerate active
scope unattended. But an unattended run still gave up too easily: on any
`ExecutorError` or invalid result the loop logged and skipped, retried nothing,
and had no notion of a crash. Worse, the strict JSONL ledgers
(`state.load_state`, `evidence.load_evidence_registry`) reject any malformed
line, so a crash mid-append leaves a truncated trailing line that breaks the
whole run and cannot be reopened without hand-editing.

## Decision

Make the loop self-healing across four failure modes, keeping every existing
guardrail (scope enforced per candidate, findings human-only, intrusive/prohibited
handoff-only).

- **Retry transient failures.** Add `TransientExecutorError(ExecutorError)`; the
  live executor raises it for a subprocess timeout. The loop retries a transient
  failure up to `max_transient_retries` (default 2) with linear backoff
  (`retry_backoff_seconds`, default 0 in tests) before treating it as permanent.
- **Re-plan on hard errors = bounded passive fallback.** On a permanent failure or
  an invalid result, the loop enqueues one `public_source_lookup` on the *same*
  candidate through the normal governed hop path (scope, state, dedup, caps, and
  auto-dispatch rules all still apply). It **never escalates action class** — the
  fallback is always passive — and a failed passive lookup is not re-planned, so
  there is no loop. Toggle `replan_passive_fallback` (default on).
- **Crash-safe resume with in-flight markers.** Before dispatching a hop the loop
  writes `contracts/inflight/<request_id>`; it removes the marker after a result is
  written or a permanent failure. On resume, a pending request that still carries a
  marker was mid-flight when a previous run crashed. An interrupted **local/passive**
  hop is idempotent and re-enqueued; an interrupted **active/intrusive** (or
  unclassifiable) hop is recorded as `interrupted` and deferred for human review —
  never silently re-fired at a target that may already have been enumerated. Toggle
  `retry_interrupted_active` (default off).
- **Run repair (`outrider/repair.py`, `outrider repair [--apply]`).** A conservative,
  read-only-by-default diagnosis that repairs only what is provably safe: it drops a
  single contiguous malformed/blank tail from a JSONL ledger (a crash mid-append),
  backing the original bytes up to `<file>.corrupt-<ts>` first, and recreates a
  missing static template file, empty ledger, or standard directory. It **never**
  fabricates evidence/approval/finding records, never edits a line in the middle of a
  ledger, and refuses (reporting `manual`) when the manifest, state log, or scope is
  missing or corrupt. It does not touch the in-flight markers, which are the loop's
  crash-recovery signal, not corruption. `orchestrate run --repair` runs a safe pass
  first and refuses to start if a human-only issue remains.

## Consequences and limitations

An unattended run now survives a flaky tool, a bad hop, a corrupted-tail ledger, and
a process crash without a human. The recovery is deliberately conservative: re-plan
can only *de-escalate* to passive and cannot increase authority; repair can only undo
a crash-truncation and recreate static scaffolding, never reconstruct lost
authorization or findings; and an interrupted active hop is handed back to a human
rather than re-fired. What repair cannot safely fix — a damaged state log, a lost
scope, mid-file ledger corruption — is surfaced for human attention instead of
guessed at. The loop still halts on an external state change, and all bounds
(hops, requests, wall-clock, per-action caps) continue to apply.
