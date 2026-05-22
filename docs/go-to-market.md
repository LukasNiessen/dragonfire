# Go-To-Market

Proofstrike's wedge is simple:

> Staged white-box red teaming for CI/CD: cheap on every PR, deeper before release, always backed by evidence.

## Launch Audience

- AppSec teams that already use SAST but still need business-logic review.
- Engineering teams adopting AI coding and wanting a stronger release gate.
- Security consultants who need repeatable source-aware assessments.
- Open-source maintainers who want better PR security review.

## Launch Motion

1. Publish the TypeScript CLI and GitHub Action workflow.
2. Ship the vulnerable fixture demo.
3. Publish a technical article comparing plain SAST output to Proofstrike's staged evidence output.
4. Invite matcher and knowledge-pack contributions.
5. Offer launch assessments for teams that want custom hotspots and policies.

## Core Demo

Use a PR that introduces:

- a missing backend authorization check;
- SQL interpolation;
- an unsigned webhook;
- an AI tool boundary issue.

Show:

- deterministic signal;
- knowledge pack selection;
- finding;
- independent validation;
- policy result;
- SARIF and PR comment.

## Commercial Layer

The open-source core remains useful. Commercial value comes from:

- hosted multi-repo dashboard;
- private pack registry;
- managed runners;
- SSO/RBAC/audit logs;
- policy governance;
- consulting rollout and custom packs.
