# Outrider Recon Report — acme.example

## Executive summary

Outrider identified two high-value external recon leads across the target's API and identity surfaces. The highest-priority lead is an exposed OpenAPI schema on `api.acme.example`.

## Scope

See `scope.yaml`.

## High-priority leads

- `api.acme.example` — exposed OpenAPI schema with object-shaped paths.
- `sso.acme.example` — identity-provider metadata and federation hints.

## Recommended next steps

- Review API authorization behavior using authorized test accounts only.
- Review OIDC/OAuth configuration exposure.
- Preserve evidence and hand off to the appropriate testing or remediation workflow.

## Boundary statement

This sample does not include exploitation or destructive validation.
