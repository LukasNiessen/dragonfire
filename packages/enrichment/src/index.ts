import fs from "node:fs";
import path from "node:path";
import {
  type AssetRecord,
  type EvidenceItem,
  createEvidence,
  normalizePath
} from "../../core/src/index.js";
import type { ArtifactSnapshot } from "../../ingest/src/index.js";
import type { OwnershipProvider } from "../../extensions/src/index.js";

export interface EnrichmentResult {
  evidence: EvidenceItem[];
  ownership: Record<string, string[]>;
}

export class EnrichmentEngine {
  constructor(private readonly ownershipProvider?: OwnershipProvider) {}

  async collect(params: { snapshot: ArtifactSnapshot; assets: AssetRecord[] }): Promise<EnrichmentResult> {
    const evidence: EvidenceItem[] = [];
    const ownership = readCodeowners(params.snapshot.rootPath);
    const providerOwnership = await this.fetchProviderOwnership(params);
    evidence.push(createEvidence({
      runId: params.snapshot.runId,
      projectId: params.snapshot.projectId,
      kind: "artifact",
      source: "proofstrike.enrichment.tech-profile",
      summary: `Detected ${params.snapshot.techProfile.tags.length} technology tag(s): ${params.snapshot.techProfile.tags.join(", ") || "none"}.`,
      raw: params.snapshot.techProfile
    }));

    const manifests = manifestAssets(params.assets);
    if (manifests.length > 0) {
      evidence.push(createEvidence({
        runId: params.snapshot.runId,
        projectId: params.snapshot.projectId,
        kind: "artifact",
        source: "proofstrike.enrichment.manifests",
        summary: `Scoped review includes ${manifests.length} manifest or deployment file(s).`,
        raw: manifests.map((asset) => ({ path: asset.filePath, language: asset.language, hash: asset.metadata.hash }))
      }));
    }

    const mergedOwnership = { ...ownership, ...providerOwnership };
    if (Object.keys(mergedOwnership).length > 0) {
      evidence.push(createEvidence({
        runId: params.snapshot.runId,
        projectId: params.snapshot.projectId,
        kind: "artifact",
        source: "proofstrike.enrichment.ownership",
        summary: `Loaded ${Object.keys(mergedOwnership).length} ownership rule(s) for triage routing.`,
        raw: mergedOwnership
      }));
    }

    const sensitiveAssets = params.assets.filter((asset) => asset.filePath && sensitivePath(asset.filePath));
    if (sensitiveAssets.length > 0) {
      evidence.push(createEvidence({
        runId: params.snapshot.runId,
        projectId: params.snapshot.projectId,
        kind: "artifact",
        source: "proofstrike.enrichment.sensitive-surfaces",
        summary: `Scoped review contains ${sensitiveAssets.length} sensitive path(s) such as auth, admin, billing, tenant, or deployment surfaces.`,
        raw: sensitiveAssets.map((asset) => asset.filePath)
      }));
    }

    return { evidence, ownership: mergedOwnership };
  }

  private async fetchProviderOwnership(params: { snapshot: ArtifactSnapshot; assets: AssetRecord[] }): Promise<Record<string, string[]>> {
    if (!this.ownershipProvider) return {};
    const ownership: Record<string, string[]> = {};
    for (const asset of params.assets) {
      if (!asset.filePath) continue;
      const record = await this.ownershipProvider.fetchOwnership({
        filePath: asset.filePath,
        rootPath: params.snapshot.rootPath,
        projectId: params.snapshot.projectId
      });
      if (record?.owners.length) ownership[asset.filePath] = record.owners;
    }
    return ownership;
  }
}

function manifestAssets(assets: AssetRecord[]): AssetRecord[] {
  return assets.filter((asset) => {
    const filePath = asset.filePath ?? asset.locator;
    return /(^|\/)(package\.json|requirements\.txt|pyproject\.toml|go\.mod|Cargo\.toml|Gemfile|composer\.json|pom\.xml|build\.gradle(?:\.kts)?|Dockerfile|docker-compose\.ya?ml|Jenkinsfile|.*\.tf|.*\.ya?ml)$/i.test(filePath);
  });
}

function sensitivePath(filePath: string): boolean {
  return /(^|\/)(auth|admin|billing|tenant|identity|session|oauth|saml|mcp|agents?|tools?|infra|k8s|deploy|terraform)(\/|$)|(?:route|controller|webhook|middleware)\./i.test(filePath);
}

function readCodeowners(rootPath: string): Record<string, string[]> {
  const candidates = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"];
  for (const relPath of candidates) {
    const absolute = path.join(rootPath, relPath);
    if (!fs.existsSync(absolute)) continue;
    const rules: Record<string, string[]> = {};
    const lines = fs.readFileSync(absolute, "utf8").split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const [pattern, ...owners] = trimmed.split(/\s+/);
      if (!pattern || owners.length === 0) continue;
      rules[normalizePath(pattern)] = owners;
    }
    return rules;
  }
  return {};
}
