# ADR 0019: Benchmark judge determinism

## Context

Outrider's coverage has been reported through self-graded smoke-test prompts. Self-grading is useful for tracking gaps but is not a measured accuracy signal, and it is not reproducible in CI. To claim accuracy honestly, Outrider needs a benchmark that runs the governed loop against a ground-truth corpus and tallies metrics the same way every time. A benchmark that depends on a live model would be neither deterministic nor runnable in continuous integration.

## Decision

Outrider adds a benchmark harness with a strictly deterministic judge as the default, and an optional offline model-assisted judge that never runs in CI.

- The corpus is a set of synthetic run folders plus expected outcomes under a versioned `ground-truth-v1` contract. Corpus fixtures are synthetic and contain no real secrets; any secret-shaped fixture is assembled from fragments so the release secret scan is not tripped.
- The harness drives the orchestrator with the stub executor (no network, no model) so a corpus run is fully reproducible.
- The deterministic judge scores each case by comparing the run's produced `discovered_candidates` and `finding_candidate` claims against the ground truth, and by measuring the `skill_result` schema-validity rate. It reports precision, recall, and coverage. Given the same corpus and fixtures, two runs produce identical metrics.
- An optional model-assisted judge may score qualitative aspects offline for exploratory analysis. It is never part of the CI path and never gates a release.
- CI runs the deterministic judge over the shipped corpus as a smoke check and asserts a metrics document is produced.

## Consequences and limitations

The benchmark replaces self-grading with reproducible numbers and gives the loop a measurement from the day it ships. Because the CI judge is deterministic and stub-driven, it measures conformance and coverage against fixtures, not live-model recon quality; the optional offline judge covers the qualitative dimension without entering CI. Reported precision and recall are only as representative as the corpus, which starts minimal and is expected to grow. The harness measures the system under test, not the real-world exploitability of any finding.
