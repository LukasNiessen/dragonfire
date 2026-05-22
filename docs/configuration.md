# Configuration

Run:

```bash
node ./dist/bin/proofstrike.js init
```

This creates:

```text
proofstrike.config.json
.proofstrike/instructions.md
.proofstrike/hotspots.yml
```

## `proofstrike.config.json`

```json
{
  "projectId": "my-service",
  "defaultStage": "pull_request",
  "outputDir": ".proofstrike/reports",
  "dataPath": ".proofstrike/proofstrike-data.json",
  "instructions": [".proofstrike/instructions.md"],
  "hotspots": [".proofstrike/hotspots.yml"],
  "packs": ["proofstrike.builtins"],
  "failOn": [
    { "severity": "critical", "validation": "real" },
    { "category": "secrets", "confidence": "high" }
  ],
  "manualReviewOn": [
    { "category": "auth", "minSeverity": "high", "validation": "real" }
  ],
  "suppressions": [],
  "runtime": {
    "agentMode": "repository-explorer",
    "modelFailureMode": "fail",
    "maxConcurrency": 2,
    "retries": 1,
    "explorationTurns": 4,
    "validationRuns": 1,
    "requestTimeoutMs": 120000
  },
  "stages": {
    "pull_request": {
      "maxCostUsd": 2,
      "graphRadius": 1
    },
    "stage": {
      "maxCostUsd": 25,
      "graphRadius": 2
    }
  }
}
```

## Instructions

`.proofstrike/instructions.md` is plain markdown. Use it to describe:

- auth model;
- tenant model;
- sensitive paths;
- security-sensitive conventions;
- common false positives.

You can configure multiple instruction files. Proofstrike also automatically loads local knowledge markdown from `.proofstrike/knowledge/*.md` into the same project-instruction channel, so teams can keep reusable project facts such as tenant-isolation rules, auth vocabulary, or sensitive business flows close to the code.

## Hotspots

`.proofstrike/hotspots.yml` marks security-sensitive paths. Hotspots produce first-class `hotspot_hint` signals, raise candidate priority, and flow into work-packet instructions.

```yaml
hotspots:
  - id: auth-boundary
    paths:
      - src/auth/**
      - src/middleware/**
    reason: Authentication and authorization boundary.
```

You can configure multiple hotspot files with the top-level `hotspots` array in `proofstrike.config.json`.

## Local Matcher Packs

Add repository-local matcher packs through `packs`:

```json
{
  "packs": [
    "proofstrike.builtins",
    ".proofstrike/custom-matchers.json"
  ]
}
```

Pack files are JSON objects with a `matchers` array. This is intended for organization-specific checks such as tenant-isolation conventions, internal framework wrappers, service-owned admin routes, or forbidden deployment patterns. Pack paths must stay inside the reviewed repository.

## Policy

`failOn` and `manualReviewOn` are ordered rule lists. A rule can match on severity, minimum severity, category, confidence, minimum confidence, validation result, evidence level, finding status, or path.

```json
{
  "failOn": [
    {
      "id": "release-critical",
      "severity": "critical",
      "validation": "real",
      "reason": "Validated critical findings block release."
    },
    {
      "id": "block-auth",
      "category": "auth",
      "minSeverity": "high",
      "path": "src/api/**"
    }
  ],
  "manualReviewOn": [
    {
      "id": "review-uncertain-auth",
      "category": "auth",
      "validation": "unknown"
    }
  ]
}
```

Supported severity values are `info`, `low`, `medium`, `high`, and `critical`. `validation` can be `real`, `reachable`, `impactful`, `general`, `unknown`, or `none`.

## Suppressions And Accepted Risk

Suppression rules let teams keep CI useful without hiding context from reports. A suppression can match a finding ID, fingerprint, category, path, or a combination of those fields.

```json
{
  "suppressions": [
    {
      "id": "accepted-legacy-admin",
      "path": "src/legacy/admin.ts",
      "category": "auth",
      "status": "accepted_risk",
      "owner": "security@example.com",
      "expiresAt": "2026-12-31T23:59:59.000Z",
      "reason": "Legacy admin panel is behind a private network migration gate."
    }
  ]
}
```

Active suppressions and accepted risks produce `pass` policy decisions with the suppression reason. Expired suppressions no longer apply.

## Optional Model Provider

Proofstrike runs without a model provider by using its deterministic static investigator and validator. To enable model-backed investigation, configure an OpenAI-compatible provider. LiteLLM works with the same shape because it exposes an OpenAI-compatible API.

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

When a provider is configured, missing keys, malformed model JSON, timeouts, and gateway errors fail loudly by default. Set `runtime.modelFailureMode` to `static-fallback` only when you explicitly want deterministic fallback with diagnostic evidence.

## Runtime Controls

- `agentMode`: `static`, `single-pass`, or `repository-explorer`.
- `modelFailureMode`: `fail` or `static-fallback`.
- `maxConcurrency`: maximum work packets processed in parallel.
- `retries`: retry count for packet/model failures.
- `staleLockMs`: age after which packet locks can be recovered.
- `explorationTurns`: maximum repository read/search turns for model-backed exploration.
- `validationRuns`: number of validation passes for consensus checking.
- `requestTimeoutMs`: per-model-call timeout.
- `directDiffOnly`: require `--diff` or `--files` so broad review cannot run accidentally.
