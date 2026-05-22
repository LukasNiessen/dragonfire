# Security

Proofstrike is a security tool, but this early implementation is source-only and read-only by design.

## Current Safety Boundary

The MVP:

- reads local repository files;
- runs deterministic source matchers;
- writes local evidence/report files;
- does not perform network attacks;
- does not execute target application code;
- does not run shell commands inside reviewed projects except for optional Git metadata lookup during ingest.

## Reporting Issues

Please report security issues privately before public disclosure.

Include:

- affected version or commit;
- reproduction steps;
- impact;
- suggested mitigation if known.

## Design Principle

Future dynamic testing must be stage-gated, scope-gated, and capability-gated. PR-stage behavior should remain source-only by default.
