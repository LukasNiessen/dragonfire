# Writing Matchers

Matchers produce signals. They should not directly produce findings.

Minimal TypeScript shape:

```ts
import type { MatcherPlugin } from "@proofstrike/scanner";

const matcher: MatcherPlugin = {
  slug: "example-risk",
  name: "Example risk",
  category: "auth",
  severity: "high",
  confidence: "medium",
  noiseTier: "low",
  async run(ctx) {
    const signals = [];
    for (const asset of ctx.files({ languages: ["javascript", "typescript"] })) {
      const text = ctx.readFile(asset.filePath);
      if (!text.includes("dangerousThing")) continue;
      signals.push(ctx.signal({
        asset,
        slug: "example-risk",
        confidence: "medium",
        weight: 0.7,
        lineNumbers: [1],
        message: "dangerousThing needs review"
      }));
    }
    return signals;
  }
};

export default matcher;
```

Good matchers include:

- clear slug;
- known language/framework scope;
- low false-positive fixture;
- useful line number;
- concise message;
- raw metadata for category/severity;
- inline examples for seeded or high-risk matchers.

## Built-In Coverage

The MVP ships 414 unique built-in matchers covering:

- secrets and secret-like public environment variables;
- SQL, NoSQL, command, deserialization, prototype-pollution, and path/file upload risks;
- auth/session issues including public admin routes, insecure cookies, JWT decode/algorithm issues, CORS, and missing auth;
- SSRF and redirect-following risks;
- XSS/dangerous HTML, postMessage, regex DoS, debug endpoints, and error leaks;
- webhooks without signature verification;
- AI-appsec and MCP tool boundaries, prompt injection, prompt leakage, and unbounded agent loops;
- GitHub Actions token permissions, `pull_request_target`, script injection, unpinned actions, and install scripts;
- weak crypto and weak randomness;
- Dockerfile, Kubernetes, and Terraform misconfigurations;
- seeded framework and runtime security surfaces for broad-stage investigation.

Matchers intentionally produce signals, not final findings. The investigator and validator decide whether a signal is strong enough to become a reportable finding.
