import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {
  type Signal,
  createSignal,
  makeId
} from "../../core/src/index.js";
import type { ArtifactSnapshot } from "../../ingest/src/index.js";
import type { StagePlan } from "../../stages/src/index.js";
import { DEFAULT_COMMAND_SANDBOX, type CommandSandboxPolicy } from "./sandbox.js";

export interface ToolAvailability {
  available: boolean;
  version?: string;
  reason?: string;
}

export interface ToolRunResult {
  toolId: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  artifactPath?: string;
}

export interface ToolAdapter {
  id: string;
  displayName: string;
  supportedStages: string[];
  isAvailable(): Promise<ToolAvailability>;
  run(params: { snapshot: ArtifactSnapshot; stagePlan: StagePlan; outputDir: string }): Promise<ToolRunResult>;
  parse(params: { result: ToolRunResult; snapshot: ArtifactSnapshot }): Promise<Signal[]>;
}

export class ExternalToolRegistry {
  private readonly tools = new Map<string, ToolAdapter>();

  register(tool: ToolAdapter): void {
    this.tools.set(tool.id, tool);
  }

  get(id: string): ToolAdapter | undefined {
    return this.tools.get(id);
  }

  all(): ToolAdapter[] {
    return [...this.tools.values()];
  }
}

export async function collectExternalToolSignals(params: {
  snapshot: ArtifactSnapshot;
  stagePlan: StagePlan;
  outputDir: string;
  registry?: ExternalToolRegistry;
  enabled?: boolean;
}): Promise<Signal[]> {
  if (!params.enabled && process.env.PROOFSTRIKE_ENABLE_EXTERNAL_TOOLS !== "1") return [];
  const registry = params.registry ?? createDefaultExternalToolRegistry();
  const signals: Signal[] = [];
  for (const toolId of params.stagePlan.tools.external) {
    const tool = registry.get(toolId);
    if (!tool) continue;
    if (!tool.supportedStages.includes(params.stagePlan.name)) continue;
    const availability = await tool.isAvailable();
    if (!availability.available) continue;
    const result = await tool.run(params);
    if (result.exitCode !== 0) continue;
    signals.push(...await tool.parse({ result, snapshot: params.snapshot }));
  }
  return signals;
}

export function createDefaultExternalToolRegistry(): ExternalToolRegistry {
  const registry = new ExternalToolRegistry();
  registry.register(new SemgrepSarifAdapter());
  registry.register(new TrivyFsAdapter());
  registry.register(new CodeQlSarifAdapter());
  return registry;
}

export class JsonSignalToolAdapter implements ToolAdapter {
  constructor(readonly id: string, readonly displayName: string, private readonly binary: string) {}

  supportedStages = ["dev", "stage", "preprod", "campaign"];

  async isAvailable(): Promise<ToolAvailability> {
    try {
      const version = execFileSync(this.binary, ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      return { available: true, version: version.trim() };
    } catch {
      return { available: false, reason: `${this.binary} is not installed or not on PATH.` };
    }
  }

  async run(params: { snapshot: ArtifactSnapshot; stagePlan: StagePlan; outputDir: string }): Promise<ToolRunResult> {
    const artifactPath = path.join(params.outputDir, `${this.id}-${params.snapshot.runId}.json`);
    fs.mkdirSync(params.outputDir, { recursive: true });
    return {
      toolId: this.id,
      exitCode: 0,
      stdout: "[]",
      stderr: "",
      artifactPath
    };
  }

  async parse(params: { result: ToolRunResult; snapshot: ArtifactSnapshot }): Promise<Signal[]> {
    if (!params.result.stdout.trim()) return [];
    try {
      const parsed = JSON.parse(params.result.stdout) as Array<{ filePath?: string; message?: string; slug?: string; line?: number }>;
      return parsed.flatMap((item) => {
        const asset = params.snapshot.files.find((file) => file.filePath === item.filePath);
        if (!asset) return [];
        return createSignal({
          runId: params.snapshot.runId,
          projectId: params.snapshot.projectId,
          assetId: asset.id,
          kind: "external_tool_hit",
          source: this.id,
          slug: item.slug ?? this.id,
          confidence: "medium",
          weight: 0.6,
          lineNumbers: item.line ? [item.line] : [],
          message: item.message ?? `${this.displayName} reported an issue.`
        });
      });
    } catch {
      return [];
    }
  }
}

export class SemgrepSarifAdapter implements ToolAdapter {
  id = "semgrep";
  displayName = "Semgrep";
  supportedStages = ["dev", "stage", "preprod", "campaign"];

  async isAvailable(): Promise<ToolAvailability> {
    return commandAvailability("semgrep", ["--version"]);
  }

  async run(params: { snapshot: ArtifactSnapshot; stagePlan: StagePlan; outputDir: string }): Promise<ToolRunResult> {
    fs.mkdirSync(params.outputDir, { recursive: true });
    const artifactPath = path.join(params.outputDir, `${this.id}-${params.snapshot.runId}.sarif`);
    const completed = runCommand("semgrep", [
      "scan",
      "--config=auto",
      "--sarif",
      "--output",
      artifactPath,
      params.snapshot.rootPath
    ], { rootPath: params.snapshot.rootPath });
    return {
      toolId: this.id,
      exitCode: completed.exitCode,
      stdout: completed.stdout,
      stderr: completed.stderr,
      artifactPath
    };
  }

  async parse(params: { result: ToolRunResult; snapshot: ArtifactSnapshot }): Promise<Signal[]> {
    if (!params.result.artifactPath || !fs.existsSync(params.result.artifactPath)) return [];
    const parsed = readJson(params.result.artifactPath);
    return signalsFromSarif({
      toolId: this.id,
      snapshot: params.snapshot,
      sarif: parsed,
      defaultSlug: "semgrep"
    });
  }
}

export class TrivyFsAdapter implements ToolAdapter {
  id = "trivy";
  displayName = "Trivy";
  supportedStages = ["dev", "stage", "preprod", "campaign"];

  async isAvailable(): Promise<ToolAvailability> {
    return commandAvailability("trivy", ["--version"]);
  }

  async run(params: { snapshot: ArtifactSnapshot; stagePlan: StagePlan; outputDir: string }): Promise<ToolRunResult> {
    fs.mkdirSync(params.outputDir, { recursive: true });
    const artifactPath = path.join(params.outputDir, `${this.id}-${params.snapshot.runId}.json`);
    const completed = runCommand("trivy", [
      "fs",
      "--format",
      "json",
      "--output",
      artifactPath,
      params.snapshot.rootPath
    ], { rootPath: params.snapshot.rootPath });
    return {
      toolId: this.id,
      exitCode: completed.exitCode,
      stdout: completed.stdout,
      stderr: completed.stderr,
      artifactPath
    };
  }

  async parse(params: { result: ToolRunResult; snapshot: ArtifactSnapshot }): Promise<Signal[]> {
    if (!params.result.artifactPath || !fs.existsSync(params.result.artifactPath)) return [];
    const parsed = readJson(params.result.artifactPath) as {
      Results?: Array<{
        Target?: string;
        Misconfigurations?: Array<{ ID?: string; Title?: string; Severity?: string; Message?: string; PrimaryURL?: string }>;
        Vulnerabilities?: Array<{ VulnerabilityID?: string; PkgName?: string; Severity?: string; Title?: string; Description?: string; PrimaryURL?: string }>;
        Secrets?: Array<{ RuleID?: string; Title?: string; Severity?: string; StartLine?: number; EndLine?: number }>;
      }>;
    };
    const signals: Signal[] = [];
    for (const result of parsed.Results ?? []) {
      const filePath = normalizeToolPath(result.Target ?? "", params.snapshot.rootPath);
      const asset = params.snapshot.files.find((file) => file.filePath === filePath);
      if (!asset) continue;
      for (const item of result.Misconfigurations ?? []) {
        signals.push(toolSignal({
          snapshot: params.snapshot,
          asset,
          source: this.id,
          slug: `trivy:${item.ID ?? "misconfiguration"}`,
          severity: item.Severity,
          line: 1,
          message: item.Title ?? item.Message ?? "Trivy reported a misconfiguration.",
          raw: item
        }));
      }
      for (const item of result.Vulnerabilities ?? []) {
        signals.push(toolSignal({
          snapshot: params.snapshot,
          asset,
          source: this.id,
          slug: `trivy:${item.VulnerabilityID ?? item.PkgName ?? "vulnerability"}`,
          severity: item.Severity,
          line: 1,
          message: item.Title ?? item.Description ?? "Trivy reported a dependency vulnerability.",
          raw: item
        }));
      }
      for (const item of result.Secrets ?? []) {
        signals.push(toolSignal({
          snapshot: params.snapshot,
          asset,
          source: this.id,
          slug: `trivy:${item.RuleID ?? "secret"}`,
          severity: item.Severity,
          line: item.StartLine ?? item.EndLine ?? 1,
          message: item.Title ?? "Trivy reported a secret.",
          raw: item
        }));
      }
    }
    return signals;
  }
}

export class CodeQlSarifAdapter implements ToolAdapter {
  id = "codeql";
  displayName = "CodeQL";
  supportedStages = ["stage", "preprod", "campaign"];

  async isAvailable(): Promise<ToolAvailability> {
    return commandAvailability("codeql", ["version"]);
  }

  async run(params: { snapshot: ArtifactSnapshot; stagePlan: StagePlan; outputDir: string }): Promise<ToolRunResult> {
    fs.mkdirSync(params.outputDir, { recursive: true });
    const databasePath = path.join(params.outputDir, `codeql-db-${params.snapshot.runId}`);
    const artifactPath = path.join(params.outputDir, `${this.id}-${params.snapshot.runId}.sarif`);
    const languages = codeQlLanguages(params.snapshot.techProfile.tags);
    if (!languages.length) {
      return {
        toolId: this.id,
        exitCode: 0,
        stdout: "",
        stderr: "CodeQL skipped: no supported language detected.",
        artifactPath
      };
    }
    const create = runCommand("codeql", [
      "database",
      "create",
      databasePath,
      "--source-root",
      params.snapshot.rootPath,
      "--language",
      languages.join(","),
      "--overwrite"
    ], { rootPath: params.snapshot.rootPath });
    if (create.exitCode !== 0) {
      return {
        toolId: this.id,
        exitCode: create.exitCode,
        stdout: create.stdout,
        stderr: create.stderr,
        artifactPath
      };
    }
    const analyze = runCommand("codeql", [
      "database",
      "analyze",
      databasePath,
      "--format",
      "sarif-latest",
      "--output",
      artifactPath,
      "security-extended",
      "security-and-quality"
    ], { rootPath: params.snapshot.rootPath });
    return {
      toolId: this.id,
      exitCode: analyze.exitCode,
      stdout: [create.stdout, analyze.stdout].filter(Boolean).join("\n"),
      stderr: [create.stderr, analyze.stderr].filter(Boolean).join("\n"),
      artifactPath
    };
  }

  async parse(params: { result: ToolRunResult; snapshot: ArtifactSnapshot }): Promise<Signal[]> {
    if (!params.result.artifactPath || !fs.existsSync(params.result.artifactPath)) return [];
    return signalsFromSarif({
      toolId: this.id,
      snapshot: params.snapshot,
      sarif: readJson(params.result.artifactPath),
      defaultSlug: "codeql"
    });
  }
}

export function createToolArtifactId(toolId: string, runId: string): string {
  return makeId("toolartifact", [toolId, runId]);
}

function commandAvailability(binary: string, args: string[]): Promise<ToolAvailability> {
  try {
    const version = execFileSync(binary, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    return Promise.resolve({ available: true, version: version.trim() });
  } catch {
    return Promise.resolve({ available: false, reason: `${binary} is not installed or not on PATH.` });
  }
}

export function runCommand(
  binary: string,
  args: string[],
  options: { rootPath?: string; cwd?: string; sandbox?: CommandSandboxPolicy; timeoutMs?: number } = {}
): { exitCode: number; stdout: string; stderr: string } {
  const sandbox = options.sandbox ?? DEFAULT_COMMAND_SANDBOX;
  const decision = sandbox.validate({ binary, args, cwd: options.cwd, rootPath: options.rootPath });
  if (!decision.allowed) {
    return { exitCode: 126, stdout: "", stderr: decision.reason ?? "Command blocked by local sandbox policy." };
  }
  try {
    const stdout = execFileSync(binary, args, {
      cwd: options.cwd ?? options.rootPath,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: options.timeoutMs ?? 10 * 60 * 1000,
      windowsHide: true
    });
    return { exitCode: 0, stdout, stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: Buffer | string; stderr?: Buffer | string; message?: string };
    return {
      exitCode: err.status ?? 1,
      stdout: bufferToString(err.stdout),
      stderr: bufferToString(err.stderr) || err.message || ""
    };
  }
}

function codeQlLanguages(tags: string[]): string[] {
  const languages = new Set<string>();
  if (tags.some((tag) => ["node", "typescript", "react", "vue", "angular", "nextjs", "express"].includes(tag))) {
    languages.add("javascript-typescript");
  }
  if (tags.includes("python")) languages.add("python");
  if (tags.includes("go")) languages.add("go");
  if (tags.includes("ruby")) languages.add("ruby");
  if (tags.includes("java") || tags.includes("kotlin") || tags.includes("jvm") || tags.includes("spring")) languages.add("java-kotlin");
  if (tags.includes("csharp") || tags.includes("dotnet")) languages.add("csharp");
  return [...languages];
}

function readJson(filePath: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return undefined;
  }
}

function signalsFromSarif(params: {
  toolId: string;
  snapshot: ArtifactSnapshot;
  sarif: unknown;
  defaultSlug: string;
}): Signal[] {
  const root = params.snapshot.rootPath;
  const sarif = params.sarif as {
    runs?: Array<{
      results?: Array<{
        ruleId?: string;
        message?: { text?: string };
        level?: string;
        locations?: Array<{
          physicalLocation?: {
            artifactLocation?: { uri?: string };
            region?: { startLine?: number };
          };
        }>;
      }>;
    }>;
  } | undefined;
  const signals: Signal[] = [];
  for (const run of sarif?.runs ?? []) {
    for (const result of run.results ?? []) {
      const location = result.locations?.[0]?.physicalLocation;
      const filePath = normalizeToolPath(location?.artifactLocation?.uri ?? "", root);
      const asset = params.snapshot.files.find((file) => file.filePath === filePath);
      if (!asset) continue;
      signals.push(toolSignal({
        snapshot: params.snapshot,
        asset,
        source: params.toolId,
        slug: `${params.defaultSlug}:${result.ruleId ?? "finding"}`,
        severity: result.level,
        line: location?.region?.startLine ?? 1,
        message: result.message?.text ?? `${params.toolId} reported a finding.`,
        raw: result
      }));
    }
  }
  return signals;
}

function toolSignal(params: {
  snapshot: ArtifactSnapshot;
  asset: ArtifactSnapshot["files"][number];
  source: string;
  slug: string;
  severity?: string;
  line: number;
  message: string;
  raw: unknown;
}): Signal {
  return createSignal({
    runId: params.snapshot.runId,
    projectId: params.snapshot.projectId,
    assetId: params.asset.id,
    kind: "external_tool_hit",
    source: params.source,
    slug: params.slug,
    confidence: "medium",
    weight: severityWeight(params.severity),
    lineNumbers: [params.line],
    message: params.message,
    raw: {
      slug: params.slug,
      category: "external-tool",
      severity: normalizeSeverity(params.severity),
      tool: params.source,
      native: params.raw
    }
  });
}

function normalizeToolPath(filePath: string, rootPath: string): string {
  const normalized = filePath.replaceAll("\\", "/").replace(/^file:\/\//, "");
  const root = rootPath.replaceAll("\\", "/");
  if (normalized.startsWith(root)) return normalized.slice(root.length).replace(/^\/+/, "");
  return normalized.replace(/^\.\//, "");
}

function severityWeight(severity?: string): number {
  const normalized = normalizeSeverity(severity);
  if (normalized === "critical") return 1;
  if (normalized === "high") return 0.85;
  if (normalized === "medium") return 0.65;
  return 0.4;
}

function normalizeSeverity(severity?: string): "low" | "medium" | "high" | "critical" {
  const value = severity?.toLowerCase();
  if (value === "error" || value === "critical") return "critical";
  if (value === "warning" || value === "high") return "high";
  if (value === "note" || value === "info" || value === "low") return "low";
  return "medium";
}

function bufferToString(value: Buffer | string | undefined): string {
  if (!value) return "";
  return typeof value === "string" ? value : value.toString("utf8");
}
