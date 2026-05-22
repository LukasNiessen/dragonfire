import type { Signal, WorkPacket } from "../../core/src/index.js";
import type { ArtifactSnapshot, ProjectInstruction } from "../../ingest/src/index.js";
import type { StagePlan } from "../../stages/src/index.js";

export interface KnowledgePack {
  id: string;
  tags: string[];
  slugs: string[];
  content: string;
}

export interface RenderedKnowledge {
  packIds: string[];
  text: string;
}

export const BUILTIN_KNOWLEDGE: readonly KnowledgePack[] = Object.freeze([
  {
    id: "core-review",
    tags: ["core"],
    slugs: [],
    content: [
      "Review only source evidence. Do not fabricate findings.",
      "Connect source, trust boundary, reachability, and impact before reporting.",
      "Search for mitigations before flagging: auth middleware, role checks, escaping, parameterization, allowlists, schema validation, and framework protections.",
      "If a mitigation fully neutralizes the issue, do not report it."
    ].join("\n")
  },
  {
    id: "tenant-isolation",
    tags: ["auth", "saas"],
    slugs: ["missing-auth", "cross-tenant-id"],
    content: [
      "Tenant isolation review:",
      "- Treat request-supplied teamId, tenantId, orgId, workspaceId, and accountId as untrusted.",
      "- Verify object access is constrained by authenticated membership or role.",
      "- Login alone is not authorization.",
      "- Mutations usually need role checks, not just membership."
    ].join("\n")
  },
  {
    id: "injection",
    tags: ["injection"],
    slugs: ["sql-injection", "nosql-injection", "command-injection", "path-traversal", "ssrf"],
    content: [
      "Injection review:",
      "- Identify the attacker-controlled source.",
      "- Identify the sink.",
      "- Check whether validation, parameterization, encoding, or allowlists break the path.",
      "- Prefer reporting concrete source-to-sink paths over generic dangerous API usage."
    ].join("\n")
  },
  {
    id: "webhook-signatures",
    tags: ["webhook"],
    slugs: ["webhook-no-signature"],
    content: [
      "Webhook review:",
      "- A webhook endpoint should verify provider signatures or equivalent shared-secret authentication.",
      "- Check raw body handling, timestamp tolerance, replay prevention, and provider-specific helpers."
    ].join("\n")
  },
  {
    id: "ai-tool-boundaries",
    tags: ["ai-appsec"],
    slugs: ["ai-tool-boundary"],
    content: [
      "AI tool boundary review:",
      "- Tool descriptions and argument schemas are not security boundaries.",
      "- Verify privileged tools enforce authorization in code.",
      "- Check that untrusted model output cannot directly trigger destructive or paid actions.",
      "- Check loop caps, spend limits, and audit logs around tool execution."
    ].join("\n")
  }
]);

export class KnowledgeRouter {
  constructor(private readonly packs: readonly KnowledgePack[] = BUILTIN_KNOWLEDGE) {}

  select(params: {
    workPacket: WorkPacket;
    signals: Signal[];
    snapshot: ArtifactSnapshot;
    stagePlan: StagePlan;
  }): KnowledgePack[] {
    const slugs = new Set(params.signals.map((signal) => signal.slug));
    const tags = new Set(params.snapshot.techProfile.tags);
    const scored = this.packs.map((pack) => ({
      pack,
      score: scorePack(pack, { slugs, tags, stagePlan: params.stagePlan })
    }));
    return scored
      .filter((item) => item.score > 0 || item.pack.id === "core-review")
      .sort((a, b) => b.score - a.score || a.pack.id.localeCompare(b.pack.id))
      .slice(0, params.stagePlan.name === "pull_request" ? 4 : 8)
      .map((item) => item.pack);
  }

  render(selection: KnowledgePack[], projectInstructions: ProjectInstruction[] = []): RenderedKnowledge {
    const sections = [
      ...selection.map((pack) => `## ${pack.id}\n${pack.content}`),
      ...projectInstructions.map((instruction) => `## Project instructions: ${instruction.path}\n${instruction.content}`)
    ];
    return {
      packIds: selection.map((pack) => pack.id),
      text: sections.join("\n\n")
    };
  }
}

function scorePack(pack: KnowledgePack, params: {
  slugs: Set<string>;
  tags: Set<string>;
  stagePlan: StagePlan;
}): number {
  let score = 0;
  for (const slug of pack.slugs) if (params.slugs.has(slug)) score += 10;
  for (const tag of pack.tags) if (params.tags.has(tag)) score += 2;
  if (params.stagePlan.name === "preprod" || params.stagePlan.name === "campaign") score += 1;
  return score;
}
