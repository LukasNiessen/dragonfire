# Dragonbreath

Dragonbreath is a staged, proof-backed white-box security review platform for CI/CD.

It starts with the practical path:

- deterministic scanner signals;
- stage-aware scope and budgets;
- project instructions and hotspots;
- source-aware investigation with deterministic local mode or optional repository-exploring model gateway;
- fact-decomposing validation and optional multi-run model consensus;
- revalidation after fixes;
- policy decisions;
- SARIF, Markdown, JSON, and PR-comment style output.

The implementation is TypeScript-first and dependency-light. It is source-only in the MVP: it does not run active network attacks, but it gives teams a CI-native release security gate with staged depth.

## Five-Minute Setup

The easiest production setup is to run Dragonbreath from npm with `npx` in GitHub Actions. You do not need to add it as a dependency to the protected repository unless you want to pin and vendor the exact CLI version in `package.json`.

1. Initialize Dragonbreath in the repository you want to protect:

```bash
npx -y dragonbreath@latest init
```

2. If you want model-backed repository exploration, edit `proofstrike.config.json` and add an OpenAI-compatible provider. Omit this block for deterministic local-only review.

```json
{
  "providers": {
    "default": {
      "type": "openai-compatible",
      "baseUrl": "https://api.openai.com/v1",
      "apiKeyEnv": "OPENAI_API_KEY",
      "defaultModel": "gpt-5.4-mini"
    }
  }
}
```

3. Add a repository secret in GitHub:

```text
OPENAI_API_KEY=<your model provider key>
```

If you omit `providers.default`, no LLM secret is required and Dragonbreath uses its deterministic investigator/validator.

4. Commit this workflow as `.github/workflows/proofstrike.yml`:

```yaml
name: Dragonbreath

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  security-review:
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
      - name: Preflight
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: npx -y dragonbreath@latest preflight --stage preprod
      - name: Pull request gate
        if: github.event_name == 'pull_request'
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: npx -y dragonbreath@latest ci --stage pull_request --diff origin/${{ github.base_ref }} --format markdown,json,sarif,pr-comment
      - name: Main branch deploy gate
        if: github.event_name == 'push' && github.ref_name == 'main'
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: npx -y dragonbreath@latest ci --stage preprod --diff HEAD~1 --revalidate-open --format markdown,json,sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .proofstrike/reports
```

5. Commit the generated files and workflow:

```bash
git add proofstrike.config.json .proofstrike .github/workflows/proofstrike.yml
git commit -m "chore: add Dragonbreath security gate"
```

The pipeline prints findings in the job log, writes Markdown/JSON/SARIF reports under `.proofstrike/reports`, uploads SARIF to GitHub code scanning, and exits nonzero when configured policy produces a blocking decision or when a CI-critical run error occurs.

## Detailed Setup

### Installation Options

Use one of these patterns:

- `npx -y dragonbreath@latest ...` for the smallest setup and automatic latest CLI.
- `npm install --save-dev dragonbreath` and `npx dragonbreath ...` when you want lockfile pinning.
- Clone this repository and run `pnpm build && node ./dist/bin/proofstrike.js ...` for local development on Dragonbreath itself.

Dragonbreath requires Node.js 22 or newer.

### Initialize Project State

Run:

```bash
npx -y dragonbreath@latest init
```

This creates:

```text
proofstrike.config.json
.proofstrike/instructions.md
.proofstrike/hotspots.yml
```

Commit those files. They are the project security context used by CI.

### Configure The Model Provider

Model-backed mode is optional. When configured, Dragonbreath uses an OpenAI-compatible API and fails loudly if credentials are missing unless you explicitly set `runtime.modelFailureMode` to `static-fallback`.

```json
{
  "providers": {
    "default": {
      "type": "openai-compatible",
      "baseUrl": "https://api.openai.com/v1",
      "apiKeyEnv": "OPENAI_API_KEY",
      "defaultModel": "gpt-5.4-mini"
    }
  },
  "runtime": {
    "agentMode": "repository-explorer",
    "modelFailureMode": "fail",
    "maxConcurrency": 2,
    "retries": 1,
    "explorationTurns": 4,
    "validationRuns": 1,
    "requestTimeoutMs": 120000
  }
}
```

For LiteLLM or another gateway, keep the same shape and change `baseUrl`, `apiKeyEnv`, and `defaultModel`.

### Choose Stage Behavior

Use these common stages:

- `pull_request`: strict diff review for PRs.
- `dev`: focused full-source review after merge to a development branch.
- `stage`: broader release-candidate review.
- `preprod`: release gate before production.
- `campaign`: deep manual/security-team campaign.

Typical CI commands:

```bash
npx -y dragonbreath@latest preflight --stage pull_request
npx -y dragonbreath@latest ci --stage pull_request --diff origin/main --format markdown,json,sarif,pr-comment
npx -y dragonbreath@latest ci --stage preprod --revalidate-open --format markdown,json,sarif
```

### Tune Policy

`failOn` blocks CI. `manualReviewOn` marks findings that should be reviewed but do not necessarily fail the build.

```json
{
  "failOn": [
    { "severity": "critical", "validation": "real" },
    { "category": "secrets", "confidence": "high" },
    { "category": "rce", "minSeverity": "high", "validation": "real" },
    { "category": "injection", "minSeverity": "high", "validation": "real" }
  ],
  "manualReviewOn": [
    { "category": "auth", "minSeverity": "high" }
  ]
}
```

Start with warn/manual-review behavior, then tighten release gates once the team has reviewed initial findings and added suppressions for accepted risk.

### Add Hotspots And Instructions

Use `.proofstrike/instructions.md` to describe your auth model, tenant model, high-value data flows, and known false positives.

Use `.proofstrike/hotspots.yml` for files that must always get attention:

```yaml
hotspots:
  - id: auth-boundary
    paths:
      - src/auth/**
      - src/middleware/**
      - app/**/route.ts
    reason: Authentication and authorization boundary.
    alwaysInclude: true
    expandRadius: 2
```

### Optional External Tools

Set this when you want Semgrep, Trivy, and CodeQL signals folded into Dragonbreath:

```yaml
env:
  PROOFSTRIKE_ENABLE_EXTERNAL_TOOLS: "1"
```

The tools must be installed on the runner. Missing tools are reported by `preflight --external-tools` and skipped during review rather than faking results.

### Local Commands

```bash
npx -y dragonbreath@latest preflight --stage pull_request
npx -y dragonbreath@latest scan --stage pull_request --files src/api/users.ts
npx -y dragonbreath@latest ci --stage pull_request --files src/api/users.ts --format markdown,json,sarif
npx -y dragonbreath@latest status
npx -y dragonbreath@latest report
npx -y dragonbreath@latest triage --min-severity medium
npx -y dragonbreath@latest revalidate
```

### Publishing This Repository

This repository is configured to publish the `dragonbreath` npm CLI package from `main` using semantic-release and Conventional Commits.

Required GitHub repository secrets:

```text
NPM_TOKEN=<npm automation token with publish rights>
GITHUB_TOKEN=<provided automatically by GitHub Actions>
```

Use Conventional Commit messages:

```text
fix: correct SARIF output path
feat: add new framework matcher pack
chore: update CI examples
```

Merging to `main` runs tests, builds the CLI, computes the next semantic version, publishes to npm, and creates the GitHub release.

## Local Development Quick Start

```bash
pnpm install
pnpm build
node ./dist/bin/proofstrike.js init
node ./dist/bin/proofstrike.js review --root fixtures/vulnerable-webapp --stage pull_request --files src/api/users.ts,src/api/admin.ts
node ./dist/bin/proofstrike.js ci --root fixtures/vulnerable-webapp --stage pull_request --files src/api/users.ts,src/api/admin.ts
node ./dist/bin/proofstrike.js status --root fixtures/vulnerable-webapp
node ./dist/bin/proofstrike.js triage --root fixtures/vulnerable-webapp
node ./dist/bin/proofstrike.js report --root fixtures/vulnerable-webapp
```

## Commands

- `dragonbreath init`
- `dragonbreath doctor`
- `dragonbreath catalog`
- `dragonbreath preflight`
- `dragonbreath scan`
- `dragonbreath review`
- `dragonbreath ci`
- `dragonbreath resume`
- `dragonbreath report`
- `dragonbreath revalidate`
- `dragonbreath status`
- `dragonbreath export`
- `dragonbreath metrics`
- `dragonbreath controls`
- `dragonbreath triage`
- `dragonbreath explain <finding-id>`
- `dragonbreath packs list`
- `dragonbreath packs install <ref>`

## Repository Layout

```text
packages/core          shared schemas, config, IDs, JSON store, policy
packages/stages        stage presets and resolver
packages/ingest        repository/file/diff/tech ingestion
packages/scanner       tech detection, matcher registry, built-in scanner rules, framework specialists
packages/graph         lightweight route/import/auth graph
packages/enrichment    run-level enrichment evidence and ownership/context summaries
packages/extensions    typed matcher, ownership, notifier, executor, and agent extension contracts
packages/preflight     CI readiness checks for store, matcher packs, models, and tools
packages/knowledge     knowledge routing and built-in security notes
packages/agents        prompt compiler, OpenAI-compatible gateway, investigator and validator runtime
packages/orchestrator  end-to-end review runner, packet execution, revalidation
packages/reporters     Markdown, JSON, SARIF, PR comment renderers
packages/tools         Semgrep, Trivy, CodeQL adapters and command execution policy
packages/cli           command-line interface
packages/testkit       fixture and test helpers
```

## Current MVP

The current source-review MVP includes:

- 500+ built-in matchers across secrets, injection, auth/session, SSRF, XSS, webhooks, AI/MCP appsec, CI/CD, supply chain, crypto, Docker, Kubernetes, Terraform/cloud, mobile, desktop, upload, deserialization, web hardening, and framework security surfaces.
- Dedicated framework-specialist matchers for stack-specific failure modes in Next.js, Express, Fastify, NestJS, tRPC, GraphQL, Django, FastAPI, Rails, Spring, .NET, Laravel, Symfony, Gin, Axum, and Electron.
- Technology detection across 40+ runtime/framework/tooling families, used to scope framework-specific scanner logic and model triage prompts.
- Stage presets for `local`, `pull_request`, `dev`, `stage`, `preprod`, and `campaign`.
- Hotspot and project-instruction loading from `.proofstrike/`.
- Static investigation and independent validation by default.
- Optional OpenAI-compatible/LiteLLM-style model configuration through `providers.default`, with repository-exploration turns, retries, timeout, usage accounting, and fail-loud behavior by default.
- Optional Semgrep, Trivy, and CodeQL signal ingestion through `PROOFSTRIKE_ENABLE_EXTERNAL_TOOLS=1`, guarded by a local command policy.
- Real revalidation that reruns matchers, adds revalidation evidence, and asks the validator to confirm whether the root cause is fixed.
- Markdown, JSON, SARIF, and PR-comment output.
- Lifecycle commands for status, export, metrics, deterministic triage, and finding explanation.
- Resumable run support for queued or errored work packets.
- Run artifacts/checkpoints for snapshots, code indexes, signals, candidates, work packets, findings, validations, and policy decisions.
- File-state tracking for repeat runs and `--since-last` incremental CI scopes.
- Local JSON matcher packs so teams can add organization-specific rules without changing Dragonbreath source.
- Typed extension registry for programmatic matcher, ownership, notifier, executor, and agent integrations.
- CI preflight checks for writable state, matcher-pack validity, model credentials, and optional external scanner availability.
- Enrichment evidence for technology profile, manifests/deployment files, ownership rules, and sensitive path surfaces.
- Config-driven `failOn`, `manualReviewOn`, suppressions, and accepted-risk rules.
- Local knowledge markdown loading from `.proofstrike/knowledge/*.md`.
- Scoped PR/diff coverage signals so changed files can enter model-backed review even when deterministic matchers do not fire.

## Docs

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [CI/CD](docs/ci-cd.md)
- [Writing Matchers](docs/writing-matchers.md)
- [Matcher Catalog](docs/matcher-catalog.md)
- [Platform Depth](docs/platform-depth.md)
- [Security Engine Hardening](docs/security-engine-hardening.md)
- [Roadmap](docs/roadmap.md)
- [Go-To-Market](docs/go-to-market.md)

