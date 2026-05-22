import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { Confidence, Severity } from "../../core/src/index.js";
import { normalizePath } from "../../core/src/index.js";
import { regexMatcher, type MatcherPlugin } from "./index.js";

export interface MatcherDefinition {
  slug: string;
  name: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  noiseTier: "low" | "medium" | "high";
  pattern: string;
  flags?: string;
  negativePattern?: string;
  message: string;
  frameworks?: string[];
  filePatterns?: string[];
  examples?: string[];
}

const matcherDefinitionSchema = z.object({
  slug: z.string().min(1),
  name: z.string().min(1),
  category: z.string().min(1),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  confidence: z.enum(["low", "medium", "high"]),
  noiseTier: z.enum(["low", "medium", "high"]),
  pattern: z.string().min(1),
  flags: z.string().optional(),
  negativePattern: z.string().optional(),
  message: z.string().min(1),
  frameworks: z.array(z.string()).optional(),
  filePatterns: z.array(z.string()).optional(),
  examples: z.array(z.string()).optional()
});

const matcherPackSchema = z.object({
  matchers: z.array(matcherDefinitionSchema)
});

export function matcherFromDefinition(definition: MatcherDefinition): MatcherPlugin {
  const flags = normalizeFlags(definition.flags);
  const filePatterns = (definition.filePatterns ?? []).map((item) => new RegExp(item, "i"));
  return regexMatcher({
    slug: definition.slug,
    name: definition.name,
    category: definition.category,
    severity: definition.severity,
    confidence: definition.confidence,
    noiseTier: definition.noiseTier,
    frameworks: definition.frameworks,
    filePatterns: definition.filePatterns,
    examples: definition.examples,
    provenance: "community",
    pattern: new RegExp(definition.pattern, flags),
    negativePattern: definition.negativePattern ? new RegExp(definition.negativePattern, flags) : undefined,
    includeIf: filePatterns.length
      ? (_text, asset) => filePatterns.some((pattern) => pattern.test(asset.filePath))
      : undefined,
    message: definition.message
  });
}

export function loadMatcherPackFile(filePath: string): MatcherPlugin[] {
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
  const pack = matcherPackSchema.parse(parsed);
  return pack.matchers.map(matcherFromDefinition);
}

export function loadMatcherPackRefs(rootPath: string, refs: string[] = []): MatcherPlugin[] {
  const matchers: MatcherPlugin[] = [];
  for (const ref of refs) {
    if (ref === "proofstrike.builtins") continue;
    const normalized = normalizePath(ref);
    if (!normalized.endsWith(".json")) continue;
    const absolute = path.isAbsolute(normalized) ? normalized : path.resolve(rootPath, normalized);
    const relative = path.relative(path.resolve(rootPath), path.resolve(absolute));
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error(`Matcher pack must be inside the reviewed repository: ${ref}`);
    }
    if (!fs.existsSync(absolute)) throw new Error(`Matcher pack not found: ${ref}`);
    matchers.push(...loadMatcherPackFile(absolute));
  }
  return matchers;
}

function normalizeFlags(flags = "i"): string {
  const unique = new Set(flags.split(""));
  unique.add("i");
  return [...unique].filter((flag) => /^[dgimsuvy]$/.test(flag)).join("");
}
