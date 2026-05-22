# CI/CD

Proofstrike is designed to run as a release-stage security gate. Use `review` for normal/manual runs and `ci` for critical-path automation that should fail loudly on run errors, work-packet errors, or blocking policy decisions.

## GitHub Actions

```yaml
name: Proofstrike

on:
  pull_request:
  push:
    branches: [dev, stage, main]

jobs:
  proofstrike:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: pnpm install --frozen-lockfile
      - run: pnpm build
      - run: node ./dist/bin/proofstrike.js preflight --stage pull_request
      - run: node ./dist/bin/proofstrike.js ci --stage pull_request --diff origin/main --format markdown,json,sarif,pr-comment
      - run: node ./dist/bin/proofstrike.js status
        if: always()
      - run: node ./dist/bin/proofstrike.js metrics
        if: always()
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .proofstrike/reports
```

For real use, package Proofstrike as an npm package or use a Docker image so the workflow does not reference a local checkout path.

## Recommended Stage Mapping

| CI/CD moment | Command shape | Intent |
|---|---|---|
| Pull request | `proofstrike ci --stage pull_request --diff origin/main` | Low-noise diff review with strict matchers and validation. |
| Direct file check | `proofstrike ci --stage pull_request --files src/api/users.ts` | Explicit file workflow for changed-file orchestrators. |
| Repeated incremental check | `proofstrike ci --stage dev --since-last` | Compare stored file hashes and review only changed files. |
| Merge to dev | `proofstrike ci --stage dev` | Focused full-repo check with strict matchers and hotspot priority. |
| Stage/preprod deploy | `proofstrike ci --stage stage` or `--stage preprod --revalidate-open` | Broader matcher profile, more graph context, revalidation, release-gate policy. |
| After fixes | `proofstrike revalidate` | Rerun matcher evidence for open findings and mark fixed root causes. |
| Security handoff | `proofstrike export --format md-dir --out .proofstrike/reports/findings` | Produce per-finding markdown for issue creation or consultant review. |
| Release triage | `proofstrike triage --min-severity medium --out .proofstrike/reports/triage.md` | Group findings into deterministic P0/P1/P2/skip action buckets. |
| Investigation | `proofstrike explain <finding-id>` | Print the evidence, validation, policy decision, and remediation for one finding. |

Run `proofstrike preflight --stage <stage>` before critical gates when you want an explicit readiness check for state writes, matcher packs, provider credentials, and optional external scanner availability.

## Optional External Tools

Proofstrike can ingest external tool findings as normal signals. The current adapters are opt-in so local runs do not unexpectedly execute heavyweight scanners.

```yaml
      - run: node ./dist/bin/proofstrike.js ci --stage stage
        env:
          PROOFSTRIKE_ENABLE_EXTERNAL_TOOLS: "1"
```

When enabled and installed on `PATH`, Proofstrike can collect Semgrep SARIF, Trivy filesystem JSON, and CodeQL SARIF output into the same evidence bundle. Missing tools are skipped instead of silently producing fake results, and command execution is constrained to approved scanner binaries.

## Exit Codes

`proofstrike review` exits nonzero if policy produces a `fail` decision. `proofstrike ci` also exits nonzero when the run records errors or any work packet ends in an error state.

The default policy is conservative:

- fail high-confidence secret exposure;
- fail validated critical findings;
- manual-review validated high findings;
- warn on uncertain findings.

Teams can override this with `failOn`, `manualReviewOn`, and `suppressions` in `proofstrike.config.json`. That is the recommended way to make PR checks cheap and conservative while making stage/preprod release gates stricter.

## Continuous Run State

Each run records file-state hashes, scope metadata, errors, work-packet statuses, model-usage estimates, and checkpoint artifacts under `.proofstrike/artifacts/<run>`. CI can choose:

- `--diff <base>` for pull-request checks.
- `--files <csv>` for direct file workflows.
- `--since-last` for repeated incremental checks based on stored file hashes.
- `resume` for queued or errored work packets from an interrupted run.
- `revalidate` or `ci --revalidate-open` after fixes or before release gates.
