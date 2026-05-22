import fs from "node:fs";
import path from "node:path";
import { Command } from "commander";
import {
  SEVERITIES,
  type AssetRecord,
  type EvidenceItem,
  type Finding,
  type PolicyEvaluation,
  type ProofstrikeConfig,
  type Severity,
  type StageName,
  type StoreData,
  type ValidationVerdict,
  JsonEvidenceStore,
  ensureDir,
  loadConfig,
  normalizePath,
  shortHash,
  writeJson
} from "../../core/src/index.js";
import { RepositoryIngestor, listSourceFiles } from "../../ingest/src/index.js";
import { BUILTIN_MATCHERS, MatcherEngine } from "../../scanner/src/index.js";
import { TECHNOLOGY_DETECTORS } from "../../scanner/src/tech.js";
import { StageResolver } from "../../stages/src/index.js";
import { RevalidationRunner, ReviewRunner } from "../../orchestrator/src/index.js";
import { renderMarkdown, renderReports } from "../../reporters/src/index.js";
import { PackManager } from "../../marketplace/src/index.js";
import { buildControlReport } from "../../standards/src/index.js";
import { runPreflight, type PreflightReport } from "../../preflight/src/index.js";

export async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program
    .name("proofstrike")
    .description("Staged, proof-backed white-box security review for CI/CD.")
    .version("0.1.0");

  program.command("init")
    .option("--root <path>", "Project root", process.cwd())
    .option("--force", "Overwrite existing Proofstrike files")
    .action(async (opts) => initCommand(opts));

  program.command("doctor")
    .option("--root <path>", "Project root", process.cwd())
    .action(async (opts) => doctorCommand(opts));

  program.command("catalog")
    .option("--format <format>", "summary|json", "summary")
    .action(async (opts) => catalogCommand(opts));

  program.command("preflight")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--stage <stage>", "Stage")
    .option("--require-model", "Require model provider credentials")
    .option("--external-tools", "Check configured external scanner availability")
    .option("--format <format>", "summary|json", "summary")
    .action(async (opts) => preflightCommand(opts));

  program.command("scan")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--stage <stage>", "Stage")
    .option("--event <event>", "Event type", "manual")
    .option("--diff <base>", "Git diff base")
    .option("--files <csv>", "Explicit files")
    .option("--since-last", "Use file-state changes since the last recorded run")
    .action(async (opts) => scanCommand(opts));

  program.command("review")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--stage <stage>", "Stage")
    .option("--event <event>", "Event type", "manual")
    .option("--branch <branch>", "Branch name")
    .option("--diff <base>", "Git diff base")
    .option("--files <csv>", "Explicit files")
    .option("--since-last", "Use file-state changes since the last recorded run")
    .option("--format <csv>", "Report formats", "markdown,json,sarif,pr-comment")
    .action(async (opts) => reviewCommand(opts));

  program.command("ci")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--stage <stage>", "Stage")
    .option("--event <event>", "Event type", "manual")
    .option("--branch <branch>", "Branch name")
    .option("--diff <base>", "Git diff base")
    .option("--files <csv>", "Explicit files")
    .option("--since-last", "Use file-state changes since the last recorded run")
    .option("--revalidate-open", "Run revalidation after the source review")
    .option("--format <csv>", "Report formats", "markdown,json,sarif,pr-comment")
    .action(async (opts) => ciCommand(opts));

  program.command("resume")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--run <runId>", "Run id")
    .option("--format <csv>", "Report formats", "markdown,json,sarif,pr-comment")
    .action(async (opts) => resumeCommand(opts));

  program.command("revalidate")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .action(async (opts) => revalidateCommand(opts));

  program.command("report")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--run <runId>", "Run id")
    .action(async (opts) => reportCommand(opts));

  program.command("status")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .action(async (opts) => statusCommand(opts));

  program.command("export")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--format <format>", "json|md-dir", "json")
    .option("--out <path>", "Output file or directory")
    .option("--min-severity <severity>", "Minimum severity")
    .option("--status <status>", "Comma-separated finding statuses")
    .option("--include-resolved", "Include fixed, suppressed, accepted-risk, and false-positive findings")
    .action(async (opts) => exportCommand(opts));

  program.command("metrics")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--min-severity <severity>", "Minimum severity", "info")
    .action(async (opts) => metricsCommand(opts));

  program.command("controls")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--format <format>", "markdown|json", "markdown")
    .action(async (opts) => controlsCommand(opts));

  program.command("triage")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .option("--min-severity <severity>", "Minimum severity", "medium")
    .option("--format <format>", "markdown|json", "markdown")
    .option("--out <path>", "Write triage report to a file")
    .action(async (opts) => triageCommand(opts));

  program.command("explain")
    .argument("<findingId>", "Finding id, fingerprint, or unique prefix")
    .option("--root <path>", "Project root", process.cwd())
    .option("--project-id <id>", "Override project id")
    .action(async (findingId, opts) => explainCommand(findingId, opts));

  program.command("packs")
    .argument("[action]", "list|install", "list")
    .argument("[ref]", "Pack reference")
    .option("--root <path>", "Project root", process.cwd())
    .action(async (action, ref, opts) => packsCommand(action, ref, opts));

  await program.parseAsync(argv, { from: "user" });
}

export async function initCommand(opts: { root?: string; force?: boolean }): Promise<void> {
  const root = path.resolve(opts.root || process.cwd());
  ensureDir(path.join(root, ".proofstrike"));
  const configPath = path.join(root, "proofstrike.config.json");
  if (!fs.existsSync(configPath) || opts.force) {
    writeJson(configPath, {
      projectId: path.basename(root).replace(/[^A-Za-z0-9_-]+/g, "-").toLowerCase() || "proofstrike-project",
      defaultStage: "pull_request",
      outputDir: ".proofstrike/reports",
      dataPath: ".proofstrike/proofstrike-data.json",
      packs: ["proofstrike.builtins"],
      runtime: {
        agentMode: "repository-explorer",
        modelFailureMode: "fail",
        maxConcurrency: 2,
        retries: 1,
        explorationTurns: 4,
        validationRuns: 1,
        requestTimeoutMs: 120000
      },
      stages: {
        pull_request: {
          maxCostUsd: 2,
          graphRadius: 1
        },
        stage: {
          maxCostUsd: 25,
          graphRadius: 2
        }
      }
    });
  }
  const instructionsPath = path.join(root, ".proofstrike", "instructions.md");
  if (!fs.existsSync(instructionsPath) || opts.force) {
    fs.writeFileSync(instructionsPath, [
      "# Proofstrike Project Instructions",
      "",
      "- Describe your authentication model here.",
      "- List sensitive paths such as auth, billing, tenant isolation, AI tools, and admin actions.",
      "- Explain project-specific false positives or accepted architectural assumptions.",
      ""
    ].join("\n"), "utf8");
  }
  const hotspotsPath = path.join(root, ".proofstrike", "hotspots.yml");
  if (!fs.existsSync(hotspotsPath) || opts.force) {
    fs.writeFileSync(hotspotsPath, [
      "hotspots:",
      "  - id: auth-boundary",
      "    paths:",
      "      - src/auth/**",
      "      - src/middleware/**",
      "    reason: Authentication and authorization boundary.",
      "  - id: ai-tools",
      "    paths:",
      "      - src/agents/**",
      "      - src/mcp/**",
      "    reason: Agent tool and MCP security boundary.",
      ""
    ].join("\n"), "utf8");
  }
  console.log(`Initialized Proofstrike in ${root}`);
}

export async function doctorCommand(opts: { root?: string }): Promise<void> {
  const root = path.resolve(opts.root || process.cwd());
  const checks = [
    ["Node version", process.version],
    ["Root", root],
    ["Config", fs.existsSync(path.join(root, "proofstrike.config.json")) ? "found" : "not found"],
    ["Instructions", fs.existsSync(path.join(root, ".proofstrike", "instructions.md")) ? "found" : "not found"],
    ["TypeScript build", fs.existsSync(path.join(root, "tsconfig.json")) ? "configured" : "not found"],
    ["Built-in matchers", String(BUILTIN_MATCHERS.length)],
    ["Technology detectors", String(TECHNOLOGY_DETECTORS.length)]
  ];
  for (const [name, value] of checks) console.log(`${name}: ${value}`);
}

export async function catalogCommand(opts: { format?: string }): Promise<void> {
  const summary = buildCatalogSummary();
  if (opts.format === "json") {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  console.log(`Built-in matchers: ${summary.total}`);
  console.log(`Technology detectors: ${summary.technologyDetectors}`);
  console.log("By category:");
  for (const [category, count] of Object.entries(summary.byCategory).sort((a, b) => b[1] - a[1])) {
    console.log(`- ${category}: ${count}`);
  }
  console.log("By noise tier:");
  for (const [tier, count] of Object.entries(summary.byNoiseTier).sort()) {
    console.log(`- ${tier}: ${count}`);
  }
  console.log("Framework-specialized tags:");
  console.log(summary.frameworks.join(", ") || "none");
}

export async function preflightCommand(opts: {
  root?: string;
  projectId?: string;
  stage?: string;
  requireModel?: boolean;
  externalTools?: boolean;
  format?: string;
}): Promise<void> {
  const root = path.resolve(opts.root || process.cwd());
  const config = configFor(root, opts.projectId);
  const stagePlan = new StageResolver().resolve({
    config,
    event: { type: "manual" },
    cliOverrides: { stage: parseStage(opts.stage || config.defaultStage) }
  });
  const report = await runPreflight({
    rootPath: root,
    config,
    stagePlan,
    requireModel: Boolean(opts.requireModel),
    externalToolsEnabled: Boolean(opts.externalTools)
  });
  if (opts.format === "json") {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(renderPreflight(report));
  }
  if (!report.ok) process.exitCode = 1;
}

export async function scanCommand(opts: CommonOptions): Promise<void> {
  const root = path.resolve(opts.root || process.cwd());
  const config = configFor(root, opts.projectId);
  const preflight = await runPreflight({
    rootPath: root,
    config,
    requireModel: Boolean(config.providers),
    externalToolsEnabled: process.env.PROOFSTRIKE_ENABLE_EXTERNAL_TOOLS === "1"
  });
  if (!preflight.ok) {
    console.log(renderPreflight(preflight));
    process.exitCode = 1;
    return;
  }
  const explicitFiles = scopedFilesForOptions(root, config, opts);
  if (opts.sinceLast && explicitFiles.length === 0) {
    console.log("No file changes found since the last recorded Proofstrike run.");
    return;
  }
  const stagePlan = new StageResolver().resolve({
    config,
    event: { type: opts.event || "manual" },
    cliOverrides: { stage: parseStage(opts.stage || config.defaultStage) }
  });
  const snapshot = await new RepositoryIngestor().ingest({
    rootPath: root,
    runId: "scan_preview",
    projectId: config.projectId,
    stagePlan,
    diffBase: opts.diff,
    explicitFiles,
    config
  });
  const signals = await new MatcherEngine().run({ snapshot, stagePlan });
  console.log(`Stage: ${stagePlan.name}`);
  console.log(`Files scoped: ${snapshot.scopedFileCount}/${snapshot.allFileCount}`);
  console.log(`Detected tech: ${snapshot.techProfile.tags.join(", ") || "none"}`);
  console.log(`Signals: ${signals.length}`);
  for (const signal of signals.slice(0, 30)) {
    const asset = snapshot.files.find((item) => item.id === signal.assetId);
    console.log(`- ${signal.slug} ${asset?.filePath || signal.assetId}:${signal.lineNumbers[0] || 1} ${signal.message}`);
  }
}

export async function reviewCommand(opts: CommonOptions & { format?: string; branch?: string }): Promise<void> {
  const root = path.resolve(opts.root || process.cwd());
  const config = configFor(root, opts.projectId);
  const explicitFiles = scopedFilesForOptions(root, config, opts);
  if (opts.sinceLast && explicitFiles.length === 0) {
    console.log("No file changes found since the last recorded Proofstrike run.");
    return;
  }
  const result = await new ReviewRunner().run({
    rootPath: root,
    config,
    stage: parseStage(opts.stage || config.defaultStage),
    event: { type: opts.event || "manual", branch: opts.branch },
    diffBase: opts.diff,
    explicitFiles
  });
  const formats = parseCsv(opts.format || "markdown,json,sarif,pr-comment");
  const outputs = renderReports(result, { rootPath: root, config, formats });
  console.log(renderSummary(result, outputs));
  if (result.policyDecisions.some((decision) => decision.decision === "fail")) {
    process.exitCode = 1;
  }
}

export async function ciCommand(opts: CommonOptions & {
  format?: string;
  branch?: string;
  revalidateOpen?: boolean;
}): Promise<void> {
  const root = path.resolve(opts.root || process.cwd());
  const config = configFor(root, opts.projectId);
  const stage = parseStage(opts.stage || config.defaultStage);
  const stagePlan = new StageResolver().resolve({
    config,
    event: { type: opts.event || "manual", branch: opts.branch },
    cliOverrides: { stage }
  });
  const preflight = await runPreflight({
    rootPath: root,
    config,
    stagePlan,
    requireModel: Boolean(config.providers),
    externalToolsEnabled: process.env.PROOFSTRIKE_ENABLE_EXTERNAL_TOOLS === "1"
  });
  if (!preflight.ok) {
    console.log(renderPreflight(preflight));
    process.exitCode = 1;
    return;
  }
  const explicitFiles = scopedFilesForOptions(root, config, opts);
  if (opts.sinceLast && explicitFiles.length === 0) {
    console.log("Proofstrike CI complete: no file changes found since the last recorded run.");
    return;
  }
  const result = await new ReviewRunner().run({
    rootPath: root,
    config,
    stage,
    event: { type: opts.event || "manual", branch: opts.branch },
    diffBase: opts.diff,
    explicitFiles
  });
  const formats = parseCsv(opts.format || "markdown,json,sarif,pr-comment");
  const outputs = renderReports(result, { rootPath: root, config, formats });
  const lines = [renderSummary(result, outputs)];
  if (opts.revalidateOpen) {
    const revalidation = await new RevalidationRunner().run({ rootPath: root, config, store: result.store });
    lines.push(`Revalidation: ${revalidation.checked} checked, ${revalidation.fixed} fixed, ${revalidation.stillOpen} still open`);
  }
  const run = result.store.getRun(result.runId);
  if (run?.errors.length) {
    lines.push(`Errors: ${run.errors.length}`);
    process.exitCode = 1;
  }
  if (result.workPackets.some((packet) => packet.status === "error")) {
    lines.push("Work packet errors detected.");
    process.exitCode = 1;
  }
  if (result.policyDecisions.some((decision) => decision.decision === "fail")) {
    process.exitCode = 1;
  }
  console.log(lines.join("\n"));
}

export async function resumeCommand(opts: { root?: string; projectId?: string; run?: string; format?: string }): Promise<void> {
  const root = path.resolve(opts.root || process.cwd());
  const config = configFor(root, opts.projectId);
  const result = await new ReviewRunner().resume({
    rootPath: root,
    config,
    runId: opts.run
  });
  const formats = parseCsv(opts.format || "markdown,json,sarif,pr-comment");
  const outputs = renderReports(result, { rootPath: root, config, formats });
  console.log(renderSummary(result, outputs));
  if (result.policyDecisions.some((decision) => decision.decision === "fail")) {
    process.exitCode = 1;
  }
}

export async function revalidateCommand(opts: { root?: string; projectId?: string }): Promise<void> {
  const root = path.resolve(opts.root || process.cwd());
  const config = configFor(root, opts.projectId);
  const result = await new RevalidationRunner().run({ rootPath: root, config });
  console.log(`Revalidation complete: ${result.checked} checked, ${result.fixed} fixed, ${result.stillOpen} still open.`);
}

export async function reportCommand(opts: { root?: string; projectId?: string; run?: string }): Promise<void> {
  const root = path.resolve(opts.root || process.cwd());
  const config = configFor(root, opts.projectId);
  const store = new JsonEvidenceStore(root, config);
  const run = opts.run ? store.getRun(opts.run) : store.latestRun(config.projectId);
  if (!run) throw new Error("No Proofstrike run found.");
  const query = store.queryRun(run.id);
  console.log(renderMarkdown({
    runId: run.id,
    stagePlan: { name: run.stage },
    snapshot: { scopedFileCount: query.assets.filter((asset) => asset.type === "file").length },
    signals: query.signals,
    findings: query.findings,
    validations: query.validations,
    policyDecisions: query.policyDecisions,
    assets: query.assets,
    evidence: query.evidenceItems
  }));
}

export async function statusCommand(opts: { root?: string; projectId?: string }): Promise<void> {
  const state = loadProjectState(opts);
  console.log(renderStatus(buildStatusSummary(state.store.data, state.config)));
}

export async function exportCommand(opts: {
  root?: string;
  projectId?: string;
  format?: string;
  out?: string;
  minSeverity?: string;
  status?: string;
  includeResolved?: boolean;
}): Promise<void> {
  const state = loadProjectState(opts);
  const format = opts.format ?? "json";
  if (format !== "json" && format !== "md-dir") throw new Error(`Unknown export format ${format}.`);
  if (format === "md-dir" && !opts.out) throw new Error("--format md-dir requires --out <directory>.");
  const bundle = buildExportBundle({
    data: state.store.data,
    config: state.config,
    minSeverity: parseSeverity(opts.minSeverity),
    statuses: opts.status ? parseCsv(opts.status) : undefined,
    includeResolved: Boolean(opts.includeResolved)
  });
  if (format === "json") {
    if (opts.out) writeJson(path.resolve(state.root, opts.out), bundle);
    else console.log(JSON.stringify(bundle, null, 2));
    return;
  }
  writeMarkdownExport(bundle, path.resolve(state.root, opts.out!));
}

export async function metricsCommand(opts: {
  root?: string;
  projectId?: string;
  minSeverity?: string;
}): Promise<void> {
  const state = loadProjectState(opts);
  const metrics = computeMetrics({
    data: state.store.data,
    config: state.config,
    minSeverity: parseSeverity(opts.minSeverity, "info")
  });
  console.log(renderMetrics(metrics));
}

export async function controlsCommand(opts: {
  root?: string;
  projectId?: string;
  format?: string;
}): Promise<void> {
  const state = loadProjectState(opts);
  const findings = projectFindings(state.store.data, state.config.projectId);
  const report = buildControlReport({
    findings,
    validations: state.store.data.validations,
    policyDecisions: state.store.data.policyDecisions
  });
  if (opts.format === "json") {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  console.log(renderControlReport(report));
}

export async function triageCommand(opts: {
  root?: string;
  projectId?: string;
  minSeverity?: string;
  format?: string;
  out?: string;
}): Promise<void> {
  const state = loadProjectState(opts);
  const result = triageFindings({
    data: state.store.data,
    config: state.config,
    minSeverity: parseSeverity(opts.minSeverity, "medium")
  });
  const format = opts.format ?? "markdown";
  const rendered = format === "json" ? JSON.stringify(result, null, 2) : renderTriage(result);
  if (opts.out) {
    const outPath = path.resolve(state.root, opts.out);
    ensureDir(path.dirname(outPath));
    fs.writeFileSync(outPath, `${rendered}\n`, "utf8");
  } else {
    console.log(rendered);
  }
}

export async function explainCommand(
  findingId: string,
  opts: { root?: string; projectId?: string }
): Promise<void> {
  const state = loadProjectState(opts);
  const explanation = explainFinding({
    data: state.store.data,
    config: state.config,
    findingId
  });
  console.log(renderFindingExplanation(explanation));
}

export async function packsCommand(action: string, ref: string | undefined, opts: { root?: string }): Promise<void> {
  const manager = new PackManager(path.resolve(opts.root || process.cwd()));
  if (action === "install") {
    if (!ref) throw new Error("packs install requires a pack reference.");
    const installed = manager.install(ref);
    console.log(`Installed pack ${installed.id} from ${installed.source}`);
    return;
  }
  for (const pack of manager.list()) {
    console.log(`${pack.id}@${pack.version} ${pack.source}`);
  }
}

export interface StatusSummary {
  projectId: string;
  latestRun?: { id: string; stage: StageName; status: string; createdAt: string; completedAt?: string };
  runs: { total: number; byStatus: Record<string, number>; byStage: Record<string, number> };
  findings: {
    total: number;
    open: number;
    byStatus: Record<string, number>;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
  };
  policy: Record<string, number>;
  validations: Record<string, number>;
}

export interface ExportedFinding {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: string;
  evidenceLevel: string;
  status: string;
  asset?: Pick<AssetRecord, "id" | "locator" | "filePath" | "language" | "owners">;
  lineNumbers: number[];
  summary: string;
  technicalDetails: string;
  impact: string;
  recommendation: string;
  validation?: ValidationVerdict;
  policy?: PolicyEvaluation;
  evidence: EvidenceItem[];
}

export interface ExportBundle {
  schemaVersion: number;
  generatedAt: string;
  projectId: string;
  filters: {
    minSeverity?: Severity;
    statuses?: string[];
    includeResolved: boolean;
  };
  totals: {
    findings: number;
  };
  findings: ExportedFinding[];
}

export interface MetricsSummary {
  projectId: string;
  generatedAt: string;
  runs: { total: number; byStatus: Record<string, number>; byStage: Record<string, number> };
  assets: { total: number; files: number; routes: number };
  signals: { total: number; bySource: Record<string, number>; bySlug: Record<string, number> };
  findings: {
    total: number;
    open: number;
    byStatus: Record<string, number>;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
  };
  validations: Record<string, number>;
  policy: Record<string, number>;
}

export type TriagePriority = "P0" | "P1" | "P2" | "skip";

export interface TriageItem {
  priority: TriagePriority;
  score: number;
  findingId: string;
  title: string;
  severity: Severity;
  category: string;
  status: string;
  asset?: string;
  policyDecision?: string;
  validation?: string | boolean;
  reason: string;
  recommendedAction: string;
}

export interface TriageResult {
  projectId: string;
  generatedAt: string;
  counts: Record<TriagePriority, number>;
  items: TriageItem[];
}

export interface FindingExplanation {
  finding: Finding;
  asset?: AssetRecord;
  validation?: ValidationVerdict;
  policy?: PolicyEvaluation;
  evidence: EvidenceItem[];
}

export interface CatalogSummary {
  total: number;
  technologyDetectors: number;
  byCategory: Record<string, number>;
  byNoiseTier: Record<string, number>;
  frameworks: string[];
}

export function buildCatalogSummary(): CatalogSummary {
  const byCategory: Record<string, number> = {};
  const byNoiseTier: Record<string, number> = {};
  const frameworks = new Set<string>();
  for (const matcher of BUILTIN_MATCHERS) {
    byCategory[matcher.category] = (byCategory[matcher.category] ?? 0) + 1;
    byNoiseTier[matcher.noiseTier] = (byNoiseTier[matcher.noiseTier] ?? 0) + 1;
    for (const framework of matcher.frameworks ?? []) frameworks.add(framework);
  }
  return {
    total: BUILTIN_MATCHERS.length,
    technologyDetectors: TECHNOLOGY_DETECTORS.length,
    byCategory,
    byNoiseTier,
    frameworks: [...frameworks].sort()
  };
}

export function buildStatusSummary(data: StoreData, config: ProofstrikeConfig): StatusSummary {
  const runs = data.runs.filter((run) => run.projectId === config.projectId);
  const findings = projectFindings(data, config.projectId);
  const latestRun = [...runs].sort((a, b) => a.createdAt.localeCompare(b.createdAt)).at(-1);
  return {
    projectId: config.projectId,
    latestRun: latestRun
      ? {
          id: latestRun.id,
          stage: latestRun.stage,
          status: latestRun.status,
          createdAt: latestRun.createdAt,
          completedAt: latestRun.completedAt
        }
      : undefined,
    runs: {
      total: runs.length,
      byStatus: countBy(runs, (run) => run.status),
      byStage: countBy(runs, (run) => run.stage)
    },
    findings: {
      total: findings.length,
      open: findings.filter((finding) => finding.status === "open").length,
      byStatus: countBy(findings, (finding) => finding.status),
      bySeverity: countBy(findings, (finding) => finding.severity),
      byCategory: countBy(findings, (finding) => finding.category)
    },
    policy: countBy(data.policyDecisions.filter((item) => item.runId && findings.some((finding) => finding.id === item.findingId)), (item) => item.decision),
    validations: validationCounts(data, findings)
  };
}

export function renderStatus(summary: StatusSummary): string {
  const lines = [
    `Proofstrike status for ${summary.projectId}`,
    `Runs: ${summary.runs.total} (${formatCounts(summary.runs.byStatus)})`,
    `Findings: ${summary.findings.total} total, ${summary.findings.open} open`,
    `Severity: ${formatCounts(summary.findings.bySeverity) || "none"}`,
    `Policy: ${formatCounts(summary.policy) || "none"}`,
    `Validation: ${formatCounts(summary.validations) || "none"}`
  ];
  if (summary.latestRun) {
    lines.splice(1, 0, `Latest run: ${summary.latestRun.id} (${summary.latestRun.stage}, ${summary.latestRun.status})`);
  }
  return lines.join("\n");
}

export function buildExportBundle(params: {
  data: StoreData;
  config: ProofstrikeConfig;
  minSeverity?: Severity;
  statuses?: string[];
  includeResolved?: boolean;
}): ExportBundle {
  const findings = filterFindings(params.data, params.config.projectId, {
    minSeverity: params.minSeverity,
    statuses: params.statuses,
    includeResolved: Boolean(params.includeResolved)
  }).map((finding) => {
    const asset = assetForFinding(params.data, finding);
    return {
      id: finding.id,
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      evidenceLevel: finding.evidenceLevel,
      status: finding.status,
      asset: asset ? {
        id: asset.id,
        locator: asset.locator,
        filePath: asset.filePath,
        language: asset.language,
        owners: asset.owners
      } : undefined,
      lineNumbers: finding.lineNumbers,
      summary: finding.summary,
      technicalDetails: finding.technicalDetails,
      impact: finding.impact,
      recommendation: finding.recommendation,
      validation: latestValidation(params.data, finding.id),
      policy: latestPolicy(params.data, finding.id),
      evidence: evidenceForFinding(params.data, finding.id)
    };
  });
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    projectId: params.config.projectId,
    filters: {
      minSeverity: params.minSeverity,
      statuses: params.statuses,
      includeResolved: Boolean(params.includeResolved)
    },
    totals: { findings: findings.length },
    findings
  };
}

export function computeMetrics(params: {
  data: StoreData;
  config: ProofstrikeConfig;
  minSeverity?: Severity;
}): MetricsSummary {
  const findings = filterFindings(params.data, params.config.projectId, {
    minSeverity: params.minSeverity,
    includeResolved: true
  });
  const runs = params.data.runs.filter((run) => run.projectId === params.config.projectId);
  const assets = params.data.assets.filter((asset) => asset.projectId === params.config.projectId);
  const signals = params.data.signals.filter((signal) => signal.projectId === params.config.projectId);
  return {
    projectId: params.config.projectId,
    generatedAt: new Date().toISOString(),
    runs: {
      total: runs.length,
      byStatus: countBy(runs, (run) => run.status),
      byStage: countBy(runs, (run) => run.stage)
    },
    assets: {
      total: assets.length,
      files: assets.filter((asset) => asset.type === "file").length,
      routes: assets.filter((asset) => asset.type === "route").length
    },
    signals: {
      total: signals.length,
      bySource: countBy(signals, (signal) => signal.source),
      bySlug: countBy(signals, (signal) => signal.slug)
    },
    findings: {
      total: findings.length,
      open: findings.filter((finding) => finding.status === "open").length,
      byStatus: countBy(findings, (finding) => finding.status),
      bySeverity: countBy(findings, (finding) => finding.severity),
      byCategory: countBy(findings, (finding) => finding.category)
    },
    validations: validationCounts(params.data, findings),
    policy: countBy(params.data.policyDecisions.filter((decision) => findings.some((finding) => finding.id === decision.findingId)), (decision) => decision.decision)
  };
}

export function renderMetrics(metrics: MetricsSummary): string {
  return [
    `Proofstrike metrics for ${metrics.projectId}`,
    `Runs: ${metrics.runs.total} (${formatCounts(metrics.runs.byStage) || "no stages"})`,
    `Assets: ${metrics.assets.total} total, ${metrics.assets.files} files, ${metrics.assets.routes} routes`,
    `Signals: ${metrics.signals.total}`,
    `Findings: ${metrics.findings.total} total, ${metrics.findings.open} open`,
    `Severity: ${formatCounts(metrics.findings.bySeverity) || "none"}`,
    `Category: ${formatCounts(metrics.findings.byCategory) || "none"}`,
    `Validation: ${formatCounts(metrics.validations) || "none"}`,
    `Policy: ${formatCounts(metrics.policy) || "none"}`
  ].join("\n");
}

export function renderControlReport(report: ReturnType<typeof buildControlReport>): string {
  const lines = [
    "# Proofstrike Controls",
    "",
    `Release risk: \`${report.releaseRisk.level}\` (${report.releaseRisk.score})`,
    `Policy: ${report.releaseRisk.blockers} blocker(s), ${report.releaseRisk.manualReview} manual review`,
    "",
    "## Standards",
    ""
  ];
  for (const [standard, count] of Object.entries(report.byStandard).sort((a, b) => a[0].localeCompare(b[0]))) {
    lines.push(`- ${standard}: ${count}`);
  }
  if (Object.keys(report.byStandard).length === 0) lines.push("- none");
  lines.push("");
  lines.push("## Top Controls");
  lines.push("");
  for (const item of report.byControl.slice(0, 12)) {
    lines.push(`- ${item.standard} ${item.controlId}: ${item.title} (${item.findings})`);
  }
  if (report.byControl.length === 0) lines.push("- none");
  lines.push("");
  lines.push("## Findings");
  lines.push("");
  for (const item of report.findings.slice(0, 20)) {
    const controls = item.controls.map((control) => `${control.standard} ${control.controlId}`).join(", ") || "unmapped";
    lines.push(`- ${item.title} (${item.severity}, weight ${item.releaseWeight}): ${controls}`);
  }
  if (report.findings.length === 0) lines.push("- none");
  return lines.join("\n");
}

export function triageFindings(params: {
  data: StoreData;
  config: ProofstrikeConfig;
  minSeverity?: Severity;
}): TriageResult {
  const findings = filterFindings(params.data, params.config.projectId, {
    minSeverity: params.minSeverity,
    includeResolved: true
  });
  const items = findings.map((finding) => triageOneFinding(params.data, finding))
    .sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  return {
    projectId: params.config.projectId,
    generatedAt: new Date().toISOString(),
    counts: {
      P0: items.filter((item) => item.priority === "P0").length,
      P1: items.filter((item) => item.priority === "P1").length,
      P2: items.filter((item) => item.priority === "P2").length,
      skip: items.filter((item) => item.priority === "skip").length
    },
    items
  };
}

export function renderTriage(result: TriageResult): string {
  const lines = [
    `# Proofstrike Triage`,
    "",
    `Project: \`${result.projectId}\``,
    `Counts: P0 ${result.counts.P0}, P1 ${result.counts.P1}, P2 ${result.counts.P2}, skip ${result.counts.skip}`,
    ""
  ];
  for (const item of result.items) {
    lines.push(`## ${item.priority} - ${item.title}`);
    lines.push("");
    lines.push(`- Finding: \`${item.findingId}\``);
    lines.push(`- Severity: \`${item.severity}\``);
    lines.push(`- Category: \`${item.category}\``);
    lines.push(`- Asset: ${item.asset ? `\`${item.asset}\`` : "n/a"}`);
    lines.push(`- Policy: \`${item.policyDecision ?? "none"}\``);
    lines.push(`- Reason: ${item.reason}`);
    lines.push(`- Action: ${item.recommendedAction}`);
    lines.push("");
  }
  return lines.join("\n");
}

export function explainFinding(params: {
  data: StoreData;
  config: ProofstrikeConfig;
  findingId: string;
}): FindingExplanation {
  const findings = projectFindings(params.data, params.config.projectId).filter((finding) =>
    finding.id === params.findingId ||
    finding.fingerprint === params.findingId ||
    finding.id.startsWith(params.findingId) ||
    finding.fingerprint.startsWith(params.findingId)
  );
  if (findings.length === 0) throw new Error(`Finding not found: ${params.findingId}`);
  if (findings.length > 1) throw new Error(`Finding id is ambiguous: ${params.findingId}`);
  const finding = findings[0]!;
  return {
    finding,
    asset: assetForFinding(params.data, finding),
    validation: latestValidation(params.data, finding.id),
    policy: latestPolicy(params.data, finding.id),
    evidence: evidenceForFinding(params.data, finding.id)
  };
}

export function renderFindingExplanation(explanation: FindingExplanation): string {
  const { finding, asset, validation, policy, evidence } = explanation;
  const lines = [
    `# ${finding.title}`,
    "",
    `Finding: \`${finding.id}\``,
    `Status: \`${finding.status}\``,
    `Severity: \`${finding.severity}\` | Confidence: \`${finding.confidence}\` | Evidence: \`${finding.evidenceLevel}\``,
    `Asset: ${asset?.filePath ?? asset?.locator ?? finding.primaryAssetId}`,
    `Lines: ${finding.lineNumbers.length ? finding.lineNumbers.join(", ") : "n/a"}`,
    `Policy: \`${policy?.decision ?? "none"}\`${policy ? ` - ${policy.reason}` : ""}`,
    "",
    "## Summary",
    "",
    finding.summary,
    "",
    "## Technical Details",
    "",
    finding.technicalDetails,
    "",
    "## Impact",
    "",
    finding.impact,
    "",
    "## Recommendation",
    "",
    finding.recommendation,
    ""
  ];
  if (validation) {
    lines.push("## Validation", "");
    lines.push(`- Real: \`${validation.real.passed}\` - ${validation.real.rationale}`);
    lines.push(`- Reachable: \`${validation.reachable.passed}\` - ${validation.reachable.rationale}`);
    lines.push(`- Impactful: \`${validation.impactful.passed}\` - ${validation.impactful.rationale}`);
    lines.push(`- General: \`${validation.general.passed}\` - ${validation.general.rationale}`);
    lines.push("");
  }
  if (evidence.length > 0) {
    lines.push("## Evidence", "");
    for (const item of evidence) {
      lines.push(`- ${item.kind} ${item.locator ?? ""}: ${item.summary}`.trim());
    }
    lines.push("");
  }
  return lines.join("\n");
}

interface CommonOptions {
  root?: string;
  projectId?: string;
  stage?: string;
  event?: string;
  diff?: string;
  files?: string;
  sinceLast?: boolean;
}

function configFor(root: string, projectId?: string): ProofstrikeConfig {
  return loadConfig(root, projectId ? { projectId } : {});
}

function renderSummary(result: Awaited<ReturnType<ReviewRunner["run"]>>, outputs: Array<{ format: string; path: string }>): string {
  const fail = result.policyDecisions.filter((decision) => decision.decision === "fail").length;
  const manual = result.policyDecisions.filter((decision) => decision.decision === "manual_review").length;
  const warn = result.policyDecisions.filter((decision) => decision.decision === "warn").length;
  const lines = [
    "Proofstrike review complete",
    `Run: ${result.runId}`,
    `Stage: ${result.stagePlan.name}`,
    `Files: ${result.snapshot.scopedFileCount}/${result.snapshot.allFileCount}`,
    `Signals: ${result.signals.length}`,
    `Findings: ${result.findings.length}`,
    `Policy: ${fail} fail, ${manual} manual review, ${warn} warn`,
    "Reports:"
  ];
  for (const output of outputs) lines.push(`- ${output.format}: ${output.path}`);
  return lines.join("\n");
}

function renderPreflight(report: PreflightReport): string {
  const lines = [report.ok ? "Proofstrike preflight passed" : "Proofstrike preflight failed"];
  if (report.issues.length === 0) {
    lines.push("- no issues");
    return lines.join("\n");
  }
  for (const issue of report.issues) {
    lines.push(`- ${issue.level.toUpperCase()} ${issue.code}: ${issue.message}`);
    if (issue.remediation) lines.push(`  ${issue.remediation}`);
  }
  return lines.join("\n");
}

function scopedFilesForOptions(root: string, config: ProofstrikeConfig, opts: CommonOptions): string[] {
  const explicit = parseCsv(opts.files);
  if (explicit.length > 0) return explicit;
  if (!opts.sinceLast) return [];
  const store = new JsonEvidenceStore(root, config);
  return changedFilesSinceLastRun(root, store.data, config.projectId);
}

export function changedFilesSinceLastRun(root: string, data: StoreData, projectId: string): string[] {
  const previous = new Map(data.fileStates
    .filter((state) => state.projectId === projectId && state.status === "active")
    .map((state) => [state.filePath, state.hash]));
  const currentFiles = listSourceFiles(root);
  if (previous.size === 0) return currentFiles;
  return currentFiles.filter((filePath) => {
    const absolute = path.join(root, filePath);
    const currentHash = shortHash(fs.readFileSync(absolute, "utf8"));
    return previous.get(normalizePath(filePath)) !== currentHash;
  });
}

function parseCsv(value?: string): string[] {
  if (!value) return [];
  return String(value).split(",").map((item) => item.trim()).filter(Boolean);
}

function parseStage(value: string): StageName {
  const allowed = ["local", "pull_request", "dev", "stage", "preprod", "campaign"] as const;
  if ((allowed as readonly string[]).includes(value)) return value as StageName;
  throw new Error(`Unknown stage ${value}`);
}

function loadProjectState(opts: { root?: string; projectId?: string }): {
  root: string;
  config: ProofstrikeConfig;
  store: JsonEvidenceStore;
} {
  const root = path.resolve(opts.root || process.cwd());
  const config = configFor(root, opts.projectId);
  return { root, config, store: new JsonEvidenceStore(root, config) };
}

function parseSeverity(value?: string, fallback?: Severity): Severity | undefined {
  if (!value) return fallback;
  const normalized = value.toLowerCase() as Severity;
  if ((SEVERITIES as readonly string[]).includes(normalized)) return normalized;
  throw new Error(`Unknown severity ${value}. Expected one of: ${SEVERITIES.join(", ")}.`);
}

function filterFindings(data: StoreData, projectId: string, opts: {
  minSeverity?: Severity;
  statuses?: string[];
  includeResolved?: boolean;
}): Finding[] {
  const normalizedStatuses = opts.statuses?.map((status) => status.trim()).filter(Boolean);
  return projectFindings(data, projectId).filter((finding) => {
    if (opts.minSeverity && !severityAtLeast(finding.severity, opts.minSeverity)) return false;
    if (normalizedStatuses?.length && !normalizedStatuses.includes(finding.status)) return false;
    if (!normalizedStatuses?.length && !opts.includeResolved && finding.status !== "open") return false;
    return true;
  });
}

function projectFindings(data: StoreData, projectId: string): Finding[] {
  return data.findings.filter((finding) => finding.projectId === projectId);
}

function severityAtLeast(actual: Severity, minimum: Severity): boolean {
  return SEVERITIES.indexOf(actual) >= SEVERITIES.indexOf(minimum);
}

function validationCounts(data: StoreData, findings: Finding[]): Record<string, number> {
  const counts = { real: 0, false_positive: 0, unknown: 0, unvalidated: 0 };
  for (const finding of findings) {
    const validation = latestValidation(data, finding.id);
    if (!validation) counts.unvalidated += 1;
    else if (validation.real.passed === true) counts.real += 1;
    else if (validation.real.passed === false) counts.false_positive += 1;
    else counts.unknown += 1;
  }
  return counts;
}

function latestValidation(data: StoreData, findingId: string): ValidationVerdict | undefined {
  return data.validations.filter((validation) => validation.findingId === findingId)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
    .at(-1);
}

function latestPolicy(data: StoreData, findingId: string): PolicyEvaluation | undefined {
  return data.policyDecisions.filter((decision) => decision.findingId === findingId)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
    .at(-1);
}

function evidenceForFinding(data: StoreData, findingId: string): EvidenceItem[] {
  return data.evidenceItems.filter((item) => item.findingId === findingId);
}

function assetForFinding(data: StoreData, finding: Finding): AssetRecord | undefined {
  return data.assets.find((asset) => asset.id === finding.primaryAssetId);
}

function countBy<T>(items: T[], fn: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const key = fn(item);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return sortCounts(counts);
}

function sortCounts(counts: Record<string, number>): Record<string, number> {
  return Object.fromEntries(Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])));
}

function formatCounts(counts: Record<string, number>): string {
  return Object.entries(counts).map(([key, value]) => `${key}: ${value}`).join(", ");
}

function writeMarkdownExport(bundle: ExportBundle, outDir: string): void {
  ensureDir(outDir);
  const index: string[] = [
    "# Proofstrike Findings Export",
    "",
    `Project: \`${bundle.projectId}\``,
    `Findings: ${bundle.findings.length}`,
    ""
  ];
  for (const finding of bundle.findings) {
    const fileName = findingFileName(finding);
    const relative = normalizePath(fileName);
    index.push(`- [${finding.severity}] ${finding.title} - ${relative}`);
    fs.writeFileSync(path.join(outDir, fileName), renderExportedFindingMarkdown(finding), "utf8");
  }
  fs.writeFileSync(path.join(outDir, "index.md"), `${index.join("\n")}\n`, "utf8");
}

function renderExportedFindingMarkdown(finding: ExportedFinding): string {
  const lines = [
    `# ${finding.title}`,
    "",
    `- Severity: \`${finding.severity}\``,
    `- Confidence: \`${finding.confidence}\``,
    `- Status: \`${finding.status}\``,
    `- Asset: ${finding.asset?.filePath ? `\`${finding.asset.filePath}\`` : "n/a"}`,
    `- Policy: \`${finding.policy?.decision ?? "none"}\``,
    "",
    finding.summary,
    "",
    "## Technical Details",
    "",
    finding.technicalDetails,
    "",
    "## Recommendation",
    "",
    finding.recommendation,
    ""
  ];
  return `${lines.join("\n")}\n`;
}

function findingFileName(finding: ExportedFinding): string {
  const safeTitle = finding.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);
  return `${finding.severity}-${safeTitle || finding.category}-${finding.id.slice(-8)}.md`;
}

function triageOneFinding(data: StoreData, finding: Finding): TriageItem {
  const validation = latestValidation(data, finding.id);
  const policy = latestPolicy(data, finding.id);
  const asset = assetForFinding(data, finding);
  if (finding.status !== "open") {
    return triageItem(finding, "skip", 0, asset, policy, validation, `Finding is ${finding.status}.`, "No immediate action; keep for audit/history.");
  }
  if (validation?.real.passed === false || policy?.decision === "pass") {
    return triageItem(finding, "skip", 5, asset, policy, validation, "Latest validation or policy does not require action.", "No immediate action unless new evidence appears.");
  }
  if (policy?.decision === "fail" || finding.severity === "critical") {
    return triageItem(finding, "P0", 100 + severityScore(finding.severity), asset, policy, validation, "Release-blocking or critical finding.", "Block release, assign an owner, and fix or create an approved accepted-risk record.");
  }
  if (finding.severity === "high") {
    const priority: TriagePriority = validation?.real.passed === true ? "P0" : "P1";
    return triageItem(finding, priority, 80, asset, policy, validation, "High-severity finding needs security owner review.", "Fix before production or require explicit security sign-off.");
  }
  if (finding.severity === "medium") {
    return triageItem(finding, "P2", 50, asset, policy, validation, "Medium-severity finding should be queued for remediation.", "Schedule remediation and revalidate after patch.");
  }
  return triageItem(finding, "skip", 10, asset, policy, validation, "Low-severity or informational finding.", "Track only if it belongs to an active hardening theme.");
}

function triageItem(
  finding: Finding,
  priority: TriagePriority,
  score: number,
  asset: AssetRecord | undefined,
  policy: PolicyEvaluation | undefined,
  validation: ValidationVerdict | undefined,
  reason: string,
  recommendedAction: string
): TriageItem {
  return {
    priority,
    score,
    findingId: finding.id,
    title: finding.title,
    severity: finding.severity,
    category: finding.category,
    status: finding.status,
    asset: asset?.filePath ?? asset?.locator,
    policyDecision: policy?.decision,
    validation: validation?.real.passed,
    reason,
    recommendedAction
  };
}

function severityScore(severity: Severity): number {
  return SEVERITIES.indexOf(severity) * 10;
}
