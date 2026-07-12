# Outrider skill contracts

Outrider skill contracts are local run artifacts under `contracts/requests/` and `contracts/results/`. They are deterministic JSON interchange records between Claude skills and the Python control layer. They are not scope authority, approval authority, authenticated identity, evidence-registry records, tool permission, or validated findings.

- `skill-request-v1.schema.json` documents request shape for `schema_version: 1`.
- `skill-result-v1.schema.json` documents result shape for `schema_version: 1`.

The Python validator is the enforcement layer. It reloads the manifest, durable state, scope, approval records, and evidence registry on every validation.
