import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import fg from "fast-glob";
import YAML from "yaml";
import {
  type AssetRecord,
  type ProofstrikeConfig,
  createAsset,
  normalizePath,
  shortHash
} from "../../core/src/index.js";
import { detectTechnology } from "../../scanner/src/tech.js";
import type { StagePlan } from "../../stages/src/index.js";

export interface FileAsset extends AssetRecord {
  type: "file";
  filePath: string;
  language: string;
}

export interface TechProfile {
  tags: string[];
  manifests: string[];
}

export interface ProjectInstruction {
  path: string;
  content: string;
}

export interface Hotspot {
  id: string;
  paths: string[];
  reason?: string;
  slugs?: string[];
  minStage?: string;
  alwaysInclude?: boolean;
  expandRadius?: number;
  knowledgePacks?: string[];
}

export interface ArtifactSnapshot {
  rootPath: string;
  projectId: string;
  runId: string;
  stage: string;
  scopeSource: "explicit_files" | "git_diff" | "git_status" | "stage_full";
  files: FileAsset[];
  allFileCount: number;
  scopedFileCount: number;
  instructions: ProjectInstruction[];
  hotspots: Hotspot[];
  techProfile: TechProfile;
}

const DEFAULT_IGNORES = [
  "**/.git/**",
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/coverage/**",
  "**/vendor/**",
  "**/generated/**",
  "**/.next/**",
  "**/.turbo/**",
  "**/.proofstrike/reports/**",
  "**/.proofstrike/artifacts/**",
  "**/.proofstrike/proofstrike-data.json"
];

const LANGUAGE_BY_EXT = new Map<string, string>([
  [".js", "javascript"],
  [".jsx", "javascript"],
  [".mjs", "javascript"],
  [".cjs", "javascript"],
  [".ts", "typescript"],
  [".tsx", "typescript"],
  [".py", "python"],
  [".rb", "ruby"],
  [".go", "go"],
  [".rs", "rust"],
  [".java", "java"],
  [".kt", "kotlin"],
  [".scala", "scala"],
  [".cs", "csharp"],
  [".php", "php"],
  [".lua", "lua"],
  [".clj", "clojure"],
  [".cljs", "clojure"],
  [".cljc", "clojure"],
  [".ex", "elixir"],
  [".exs", "elixir"],
  [".erl", "erlang"],
  [".cr", "crystal"],
  [".dart", "dart"],
  [".swift", "swift"],
  [".cls", "apex"],
  [".apex", "apex"],
  [".proto", "protobuf"],
  [".tf", "terraform"],
  [".toml", "toml"],
  [".gradle", "gradle"],
  [".kts", "kotlin"],
  [".xml", "xml"],
  [".plist", "plist"],
  [".properties", "properties"],
  [".yml", "yaml"],
  [".yaml", "yaml"],
  [".json", "json"],
  [".md", "markdown"],
  [".html", "html"],
  [".css", "css"]
]);

export class RepositoryIngestor {
  async ingest(params: {
    rootPath: string;
    runId: string;
    projectId: string;
    stagePlan: StagePlan;
    diffBase?: string;
    explicitFiles?: string[];
    config?: Pick<ProofstrikeConfig, "instructions" | "hotspots">;
  }): Promise<ArtifactSnapshot> {
    const root = path.resolve(params.rootPath);
    const allFiles = listSourceFiles(root);
    const scopedPaths = resolveScope({
      root,
      allFiles,
      stagePlan: params.stagePlan,
      diffBase: params.diffBase,
      explicitFiles: params.explicitFiles ?? []
    });
    const scopeSource = scopeSourceFor({
      stagePlan: params.stagePlan,
      diffBase: params.diffBase,
      explicitFiles: params.explicitFiles ?? []
    });
    const files = scopedPaths.map((filePath) =>
      buildFileAsset({ root, projectId: params.projectId, runId: params.runId, filePath })
    );
    return {
      rootPath: root,
      projectId: params.projectId,
      runId: params.runId,
      stage: params.stagePlan.name,
      scopeSource,
      files,
      allFileCount: allFiles.length,
      scopedFileCount: files.length,
      instructions: loadInstructions(root, params.config),
      hotspots: loadHotspots(root, params.config),
      techProfile: detectTech(root, allFiles)
    };
  }
}

export function listSourceFiles(rootPath: string): string[] {
  return fg.sync(["**/*"], {
    cwd: rootPath,
    onlyFiles: true,
    dot: true,
    ignore: DEFAULT_IGNORES,
    absolute: false
  })
    .map(normalizePath)
    .filter(isProbablyTextSource)
    .sort();
}

export function resolveScope(params: {
  root: string;
  allFiles: string[];
  stagePlan: Pick<StagePlan, "scopeMode" | "maxFiles">;
  diffBase?: string;
  explicitFiles: string[];
}): string[] {
  if (params.explicitFiles.length > 0) {
    return params.explicitFiles
      .map(normalizePath)
      .filter((filePath) => fs.existsSync(path.join(params.root, filePath)))
      .sort();
  }
  if (params.stagePlan.scopeMode.startsWith("diff")) {
    const diffFiles = params.diffBase ? gitDiffFiles(params.root, params.diffBase) : gitChangedFiles(params.root);
    const existing = diffFiles.filter((filePath) => fs.existsSync(path.join(params.root, filePath)) && isProbablyTextSource(filePath));
    return existing.length > 0 ? existing.sort() : params.allFiles.slice(0, numericMax(params.stagePlan.maxFiles, 100));
  }
  return params.allFiles.slice(0, numericMax(params.stagePlan.maxFiles, params.allFiles.length)).sort();
}

export function gitDiffFiles(rootPath: string, base: string): string[] {
  try {
    const output = execFileSync("git", ["diff", "--name-only", base, "--"], {
      cwd: rootPath,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    });
    return output.split(/\r?\n/).map(normalizePath).filter(Boolean);
  } catch {
    return [];
  }
}

export function gitChangedFiles(rootPath: string): string[] {
  try {
    const output = execFileSync("git", ["status", "--short"], {
      cwd: rootPath,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    });
    return output
      .split(/\r?\n/)
      .map((line) => line.slice(3).trim())
      .map(normalizePath)
      .filter(Boolean);
  } catch {
    return [];
  }
}

export function buildFileAsset(params: {
  root: string;
  projectId: string;
  runId: string;
  filePath: string;
}): FileAsset {
  const abs = path.join(params.root, params.filePath);
  const text = fs.readFileSync(abs, "utf8");
  const language = languageForPath(params.filePath, text);
  const asset = createAsset({
    projectId: params.projectId,
    runId: params.runId,
    type: "file",
    locator: params.filePath,
    filePath: params.filePath,
    language,
    metadata: {
      hash: shortHash(text),
      bytes: Buffer.byteLength(text),
      lines: text.split(/\r?\n/).length
    }
  }) as FileAsset;
  asset.type = "file";
  asset.filePath = normalizePath(params.filePath);
  asset.language = language;
  asset.lastHash = asset.metadata.hash as string;
  return asset;
}

export function readFileText(rootPath: string, filePath: string): string {
  return fs.readFileSync(path.join(rootPath, filePath), "utf8");
}

export function languageForPath(filePath: string, text = ""): string {
  const lower = filePath.toLowerCase();
  if (lower.endsWith("dockerfile") || lower.includes("/dockerfile")) return "dockerfile";
  const ext = path.extname(lower);
  if (LANGUAGE_BY_EXT.has(ext)) return LANGUAGE_BY_EXT.get(ext) ?? "unknown";
  if (text.startsWith("#!/usr/bin/env node")) return "javascript";
  if (text.startsWith("#!/usr/bin/env python")) return "python";
  return "unknown";
}

export function detectTech(rootPath: string, files: string[]): TechProfile {
  const packageJson = readJson(rootPath, "package.json") as
    | { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
    | undefined;
  const deps = { ...(packageJson?.dependencies ?? {}), ...(packageJson?.devDependencies ?? {}) };
  return detectTechnology({
    files,
    packageDependencies: deps,
    readText: (filePath) => {
      try {
        return fs.readFileSync(path.join(rootPath, filePath), "utf8");
      } catch {
        return undefined;
      }
    }
  });
}

export function loadInstructions(
  rootPath: string,
  config: Pick<ProofstrikeConfig, "instructions"> = { instructions: [".proofstrike/instructions.md"] }
): ProjectInstruction[] {
  const configured = config.instructions?.length ? config.instructions : [".proofstrike/instructions.md"];
  const candidates = uniquePaths([
    ...expandConfiguredPaths(rootPath, configured),
    ...expandConfiguredPaths(rootPath, ["PROOFSTRIKE.md", ".proofstrike/knowledge/*.md"])
  ]);
  return candidates
    .filter((filePath) => fs.existsSync(filePath))
    .map((filePath) => ({
      path: normalizePath(path.relative(rootPath, filePath)),
      content: fs.readFileSync(filePath, "utf8")
    }));
}

export function loadHotspots(
  rootPath: string,
  config: Pick<ProofstrikeConfig, "hotspots"> = { hotspots: [".proofstrike/hotspots.yml"] }
): Hotspot[] {
  const configured = config.hotspots?.length ? config.hotspots : [".proofstrike/hotspots.yml"];
  const hotspots: Hotspot[] = [];
  for (const filePath of uniquePaths(expandConfiguredPaths(rootPath, configured))) {
    if (!fs.existsSync(filePath)) continue;
    const parsed = YAML.parse(fs.readFileSync(filePath, "utf8")) as { hotspots?: Hotspot[] } | null;
    if (Array.isArray(parsed?.hotspots)) hotspots.push(...parsed.hotspots);
  }
  return hotspots;
}

function numericMax(value: number | "unlimited", fallback: number): number {
  return value === "unlimited" ? fallback : Number(value || fallback);
}

function isProbablyTextSource(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".lock")) return false;
  const ext = path.extname(lower);
  const base = path.basename(lower);
  return LANGUAGE_BY_EXT.has(ext) || lower.endsWith("dockerfile") || lower === "package.json" || base === "jenkinsfile";
}

function readJson(rootPath: string, relPath: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(path.join(rootPath, relPath), "utf8"));
  } catch {
    return undefined;
  }
}

function scopeSourceFor(params: {
  stagePlan: Pick<StagePlan, "scopeMode">;
  diffBase?: string;
  explicitFiles: string[];
}): ArtifactSnapshot["scopeSource"] {
  if (params.explicitFiles.length > 0) return "explicit_files";
  if (params.stagePlan.scopeMode.startsWith("diff")) return params.diffBase ? "git_diff" : "git_status";
  return "stage_full";
}

function expandConfiguredPaths(rootPath: string, patterns: string[]): string[] {
  const paths: string[] = [];
  for (const pattern of patterns) {
    const normalized = normalizePath(pattern);
    if (normalized.includes("*")) {
      paths.push(...fg.sync(normalized, {
        cwd: rootPath,
        onlyFiles: true,
        dot: true,
        absolute: true,
        ignore: DEFAULT_IGNORES
      }));
      continue;
    }
    paths.push(path.resolve(rootPath, normalized));
  }
  return paths;
}

function uniquePaths(paths: string[]): string[] {
  return [...new Set(paths.map((filePath) => path.resolve(filePath)))];
}
