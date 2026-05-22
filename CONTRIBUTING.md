# Contributing

Proofstrike is structured as a small monorepo. The fastest useful contributions are:

- matchers with positive and negative fixtures;
- framework-specific knowledge notes;
- reporter improvements;
- stage policy presets;
- route/auth graph extractors;
- docs and CI examples.

## Development

```bash
node ./bin/proofstrike.js doctor
node tests/run-tests.js
node ./bin/proofstrike.js scan --root fixtures/vulnerable-webapp --stage stage --files src/api/users.js,src/api/admin.js,src/api/webhook.js
```

## Matcher Quality Bar

A matcher should:

- produce a signal, not a finding;
- include useful line numbers;
- avoid generated/vendor files;
- have at least one positive and one negative fixture over time;
- explain the security hypothesis in plain language.

## Architecture Rule

Keep package responsibilities narrow:

- `scanner` finds signals;
- `agents` propose and validate findings;
- `core` owns schemas and storage;
- `orchestrator` coordinates;
- `reporters` render output.
