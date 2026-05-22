import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

export const STAGES = ["local", "pull_request", "dev", "stage", "preprod", "campaign"] as const;
export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export const CONFIDENCES = ["low", "medium", "high"] as const;
export const EVIDENCE_LEVELS = [
  "suspicion",
  "static_match",
  "static_corroboration",
  "source_reasoned",
  "reachable_reasoned",
  "sandbox_reproduced",
  "root_cause_explained",
  "patch_validated"
] as const;
export const POLICY_DECISIONS = ["pass", "warn", "manual_review", "fail"] as const;

export type StageName = (typeof STAGES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type Confidence = (typeof CONFIDENCES)[number];
export type EvidenceLevel = (typeof EVIDENCE_LEVELS)[number];
export type PolicyDecision = (typeof POLICY_DECISIONS)[number];

export type AssetType =
  | "file"
  | "route"
  | "symbol"
  | "package"
  | "iac_resource"
  | "ci_workflow"
  | "ai_prompt"
  | "ai_tool"
  | "mcp_server"
  | "bundle"
  | "traffic";

export type SignalKind =
  | "matcher_hit"
  | "external_tool_hit"
  | "graph_reachability"
  | "hotspot_hint"
  | "history_hit"
  | "dependency_delta"
  | "ai_pretriage"
  | "negative_signal";

export type FindingStatus = "open" | "fixed" | "accepted_risk" | "suppressed" | "false_positive";

export interface OwnerRef {
  kind: "user" | "team" | "unknown";
  name: string;
  source?: string;
}

export interface AssetRecord {
  id: string;
  projectId: string;
  type: AssetType;
  locator: string;
  displayName: string;
  fingerprint: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  language?: string;
  frameworkTags: string[];
  owners: OwnerRef[];
  sensitivity: string[];
  metadata: Record<string, unknown>;
  firstSeenRunId: string;
  lastSeenRunId: string;
  lastHash?: string;
  status: "active" | "deleted" | "ignored";
}

export interface Signal {
  id: string;
  runId: string;
  projectId: string;
  assetId: string;
  kind: SignalKind;
  source: string;
  slug: string;
  confidence: Confidence;
  weight: number;
  lineNumbers: number[];
  snippet?: string;
  message: string;
  raw?: unknown;
  createdAt: string;
}

export interface Candidate {
  id: string;
  runId: string;
  projectId: string;
  primaryAssetId: string;
  relatedAssetIds: string[];
  slugs: string[];
  signalIds: string[];
  riskScore: number;
  riskBreakdown: Record<string, unknown>;
  stage: StageName;
  status: "planned" | "processing" | "analyzed" | "skipped" | "error";
  reason: string;
}

export interface PacketBudget {
  maxCostUsd: number;
  maxPromptChars: number;
  maxToolCalls?: number;
}

export interface WorkPacket {
  id: string;
  runId: string;
  projectId: string;
  stage: StageName;
  agentKind: string;
  primaryAssetId: string;
  assetIds: string[];
  candidateIds: string[];
  signalIds: string[];
  codeContext: unknown[];
  graphContext: unknown[];
  knowledgePackIds: string[];
  projectInstructionIds: string[];
  historyRefs: string[];
  budget: PacketBudget;
  outputSchema: "finding_array" | "validation_verdict" | "fix_plan";
  status: "queued" | "running" | "done" | "error" | "cancelled";
}

export interface Finding {
  id: string;
  projectId: string;
  firstRunId: string;
  latestRunId: string;
  primaryAssetId: string;
  relatedAssetIds: string[];
  title: string;
  category: string;
  cwe: string[];
  severity: Severity;
  confidence: Confidence;
  evidenceLevel: EvidenceLevel;
  summary: string;
  technicalDetails: string;
  impact: string;
  recommendation: string;
  assumptions: string[];
  negativeEvidence: string[];
  lineNumbers: number[];
  fingerprint: string;
  status: FindingStatus;
  producedBy: {
    agentKind: string;
    model?: string;
    workPacketId: string;
  };
  createdAt: string;
  updatedAt: string;
}

export interface EvidenceItem {
  id: string;
  findingId?: string;
  candidateId?: string;
  runId: string;
  projectId: string;
  assetId?: string;
  kind:
    | "code"
    | "matcher"
    | "graph"
    | "external_tool"
    | "model_reasoning_summary"
    | "validation"
    | "negative_evidence"
    | "patch"
    | "test"
    | "artifact";
  source: string;
  summary: string;
  locator?: string;
  startLine?: number;
  endLine?: number;
  artifactUri?: string;
  raw?: unknown;
  createdAt: string;
}

export interface AxisVerdict {
  passed: boolean | "unknown";
  confidence: Confidence;
  rationale: string;
}

export interface ValidationVerdict {
  id: string;
  findingId: string;
  runId: string;
  validatorKind: string;
  model?: string;
  real: AxisVerdict;
  reachable: AxisVerdict;
  impactful: AxisVerdict;
  general: AxisVerdict;
  fixed?: AxisVerdict;
  adjustedSeverity?: Severity;
  adjustedEvidenceLevel?: EvidenceLevel;
  reasoningSummary: string;
  counterArgument: string;
  requiredFollowup: string[];
  createdAt: string;
}

export interface PolicyEvaluation {
  id: string;
  runId: string;
  findingId: string;
  decision: PolicyDecision;
  reason: string;
  ruleId: string;
  createdAt: string;
}

export interface PolicyRule {
  [key: string]: unknown;
  id?: string;
  decision?: PolicyDecision;
  severity?: Severity;
  minSeverity?: Severity;
  category?: string | string[];
  confidence?: Confidence;
  minConfidence?: Confidence;
  validation?: "real" | "reachable" | "impactful" | "general" | "unknown" | "none";
  evidenceAtLeast?: EvidenceLevel;
  status?: FindingStatus | FindingStatus[];
  path?: string;
  reason?: string;
}

export interface SuppressionRule {
  [key: string]: unknown;
  id?: string;
  findingId?: string;
  fingerprint?: string;
  category?: string | string[];
  path?: string;
  status?: "suppressed" | "accepted_risk" | "false_positive";
  reason?: string;
  owner?: string;
  expiresAt?: string;
}

export interface RunRecord {
  id: string;
  projectId: string;
  rootPath: string;
  stage: StageName;
  eventType: string;
  status: "running" | "done" | "failed_policy" | "error";
  createdAt: string;
  completedAt?: string;
  scope?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  git: Record<string, string | undefined>;
  stats: Record<string, number>;
  errors: string[];
}

export interface FileStateRecord {
  id: string;
  projectId: string;
  filePath: string;
  language?: string;
  hash?: string;
  bytes?: number;
  lines?: number;
  firstSeenRunId: string;
  lastSeenRunId: string;
  status: "active" | "deleted";
  updatedAt: string;
}

export interface ModelUsageRecord {
  id: string;
  runId: string;
  projectId: string;
  workPacketId?: string;
  provider?: string;
  model?: string;
  operation: "investigation" | "validation" | "revalidation";
  promptChars: number;
  responseChars: number;
  estimatedPromptTokens: number;
  estimatedResponseTokens: number;
  estimatedCostUsd: number;
  attempts: number;
  createdAt: string;
  raw?: unknown;
}

export interface ProofstrikeRuntimeConfig {
  maxConcurrency?: number;
  retries?: number;
  staleLockMs?: number;
  modelFailureMode?: "fail" | "static-fallback";
  agentMode?: "static" | "single-pass" | "repository-explorer";
  explorationTurns?: number;
  validationRuns?: number;
  requestTimeoutMs?: number;
  directDiffOnly?: boolean;
}

export interface ProofstrikeConfig {
  projectId: string;
  defaultStage: StageName;
  outputDir: string;
  dataPath: string;
  instructions: string[];
  hotspots: string[];
  failOn: PolicyRule[];
  manualReviewOn: PolicyRule[];
  suppressions: SuppressionRule[];
  stages: Record<string, Record<string, unknown>>;
  providers?: Record<string, unknown>;
  runtime?: ProofstrikeRuntimeConfig;
  packs?: string[];
}

export interface StoreData {
  schemaVersion: number;
  runs: RunRecord[];
  assets: AssetRecord[];
  signals: Signal[];
  candidates: Candidate[];
  workPackets: WorkPacket[];
  findings: Finding[];
  evidenceItems: EvidenceItem[];
  validations: ValidationVerdict[];
  policyDecisions: PolicyEvaluation[];
  suppressions: unknown[];
  packVersions: unknown[];
  modelUsage: ModelUsageRecord[];
  fileStates: FileStateRecord[];
}

export const configSchema = z.object({
  projectId: z.string().min(1),
  defaultStage: z.enum(STAGES).default("pull_request"),
  outputDir: z.string().default(".proofstrike/reports"),
  dataPath: z.string().default(".proofstrike/proofstrike-data.json"),
  instructions: z.array(z.string()).default([".proofstrike/instructions.md"]),
  hotspots: z.array(z.string()).default([".proofstrike/hotspots.yml"]),
  failOn: z.array(z.record(z.string(), z.unknown())).default([
    { severity: "critical", validation: "real" },
    { category: "secrets", confidence: "high" }
  ]),
  manualReviewOn: z.array(z.record(z.string(), z.unknown())).default([]),
  suppressions: z.array(z.record(z.string(), z.unknown())).default([]),
  stages: z.record(z.string(), z.record(z.string(), z.unknown())).default({}),
  providers: z.record(z.string(), z.unknown()).optional(),
  runtime: z.object({
    maxConcurrency: z.number().int().positive().optional(),
    retries: z.number().int().min(0).optional(),
    staleLockMs: z.number().int().positive().optional(),
    modelFailureMode: z.enum(["fail", "static-fallback"]).optional(),
    agentMode: z.enum(["static", "single-pass", "repository-explorer"]).optional(),
    explorationTurns: z.number().int().positive().optional(),
    validationRuns: z.number().int().positive().optional(),
    requestTimeoutMs: z.number().int().positive().optional(),
    directDiffOnly: z.boolean().optional()
  }).optional(),
  packs: z.array(z.string()).optional()
});

export const DEFAULT_CONFIG: ProofstrikeConfig = Object.freeze({
  projectId: "proofstrike-project",
  defaultStage: "pull_request",
  outputDir: ".proofstrike/reports",
  dataPath: ".proofstrike/proofstrike-data.json",
  instructions: [".proofstrike/instructions.md"],
  hotspots: [".proofstrike/hotspots.yml"],
  failOn: [
    { severity: "critical", validation: "real" },
    { category: "secrets", confidence: "high" }
  ] as PolicyRule[],
  manualReviewOn: [] as PolicyRule[],
  suppressions: [] as SuppressionRule[],
  runtime: {
    maxConcurrency: 2,
    retries: 1,
    staleLockMs: 15 * 60 * 1000,
    modelFailureMode: "fail",
    agentMode: "repository-explorer",
    explorationTurns: 4,
    validationRuns: 1,
    requestTimeoutMs: 120000
  } as ProofstrikeRuntimeConfig,
  stages: {}
});

export function nowIso(): string {
  return new Date().toISOString();
}

export function stableHash(value: unknown): string {
  const normalized = typeof value === "string" ? value : stableJson(value);
  return crypto.createHash("sha256").update(normalized).digest("hex");
}

export function shortHash(value: unknown, length = 12): string {
  return stableHash(value).slice(0, length);
}

export function stableJson(value: unknown): string {
  return JSON.stringify(sortObject(value));
}

export function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, inner]) => [key, sortObject(inner)])
  );
}

export function makeId(prefix: string, parts: unknown[] = []): string {
  return `${prefix}_${shortHash(parts)}`;
}

export function normalizePath(filePath: string): string {
  return filePath.replaceAll("\\", "/").replace(/^\.\//, "");
}

export function ensureDir(dirPath: string): void {
  fs.mkdirSync(dirPath, { recursive: true });
}

export function readJsonIfExists<T>(filePath: string, fallback: T): T {
  if (!fs.existsSync(filePath)) return fallback;
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

export function writeJson(filePath: string, value: unknown): void {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export function loadConfig(rootPath: string, overrides: Partial<ProofstrikeConfig> = {}): ProofstrikeConfig {
  const jsonPath = path.join(rootPath, "proofstrike.config.json");
  const fromFile = readJsonIfExists<Record<string, unknown>>(jsonPath, {});
  const merged = deepMerge(DEFAULT_CONFIG, fromFile, overrides);
  return configSchema.parse(merged);
}

export function deepMerge<T>(...objects: unknown[]): T {
  const result: Record<string, unknown> = {};
  for (const object of objects) {
    if (!object || typeof object !== "object") continue;
    for (const [key, value] of Object.entries(object)) {
      const existing = result[key];
      if (
        value &&
        typeof value === "object" &&
        !Array.isArray(value) &&
        existing &&
        typeof existing === "object" &&
        !Array.isArray(existing)
      ) {
        result[key] = deepMerge(existing as Record<string, unknown>, value as Record<string, unknown>);
      } else {
        result[key] = value;
      }
    }
  }
  return result as T;
}

export function unique<T>(values: T[]): T[] {
  return Array.from(new Set(values.filter(Boolean)));
}

export function createAsset(params: {
  projectId: string;
  runId: string;
  type?: AssetType;
  locator: string;
  filePath?: string;
  language?: string;
  metadata?: Record<string, unknown>;
}): AssetRecord {
  const normalizedLocator = normalizePath(params.locator ?? params.filePath ?? "unknown");
  return {
    id: makeId("asset", [params.projectId, params.type ?? "file", normalizedLocator]),
    projectId: params.projectId,
    type: params.type ?? "file",
    locator: normalizedLocator,
    displayName: normalizedLocator,
    fingerprint: makeId("fp", [params.type ?? "file", normalizedLocator]),
    filePath: params.filePath ? normalizePath(params.filePath) : undefined,
    language: params.language,
    frameworkTags: [],
    owners: [],
    sensitivity: [],
    metadata: params.metadata ?? {},
    firstSeenRunId: params.runId,
    lastSeenRunId: params.runId,
    status: "active"
  };
}

export function createRun(params: {
  projectId: string;
  rootPath: string;
  stage: StageName;
  eventType?: string;
  git?: Record<string, string | undefined>;
  scope?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}): RunRecord {
  const createdAt = nowIso();
  return {
    id: makeId("run", [params.projectId, params.rootPath, params.stage, params.eventType ?? "manual", createdAt]),
    projectId: params.projectId,
    rootPath: params.rootPath,
    stage: params.stage,
    eventType: params.eventType ?? "manual",
    status: "running",
    createdAt,
    scope: params.scope,
    metadata: params.metadata,
    git: params.git ?? {},
    stats: {
      assets: 0,
      signals: 0,
      candidates: 0,
      workPackets: 0,
      findings: 0,
      validations: 0
    },
    errors: []
  };
}

export function createSignal(params: {
  runId: string;
  projectId: string;
  assetId: string;
  kind?: SignalKind;
  source: string;
  slug: string;
  confidence?: Confidence;
  weight?: number;
  lineNumbers?: number[];
  snippet?: string;
  message: string;
  raw?: unknown;
}): Signal {
  return {
    id: makeId("signal", [
      params.runId,
      params.assetId,
      params.kind ?? "matcher_hit",
      params.source,
      params.slug,
      params.lineNumbers ?? [],
      params.snippet
    ]),
    runId: params.runId,
    projectId: params.projectId,
    assetId: params.assetId,
    kind: params.kind ?? "matcher_hit",
    source: params.source,
    slug: params.slug,
    confidence: params.confidence ?? "medium",
    weight: params.weight ?? 0.5,
    lineNumbers: params.lineNumbers ?? [],
    snippet: params.snippet,
    message: params.message,
    raw: params.raw,
    createdAt: nowIso()
  };
}

export function createCandidate(params: {
  runId: string;
  projectId: string;
  primaryAssetId: string;
  relatedAssetIds?: string[];
  signals: Signal[];
  stage: StageName;
}): Candidate {
  const slugs = unique(params.signals.map((signal) => signal.slug));
  const riskScore = Number(
    Math.min(1, params.signals.reduce((sum, signal) => sum + Number(signal.weight || 0), 0) / 2).toFixed(3)
  );
  return {
    id: makeId("candidate", [params.runId, params.primaryAssetId, slugs]),
    runId: params.runId,
    projectId: params.projectId,
    primaryAssetId: params.primaryAssetId,
    relatedAssetIds: unique([params.primaryAssetId, ...(params.relatedAssetIds ?? [])]),
    slugs,
    signalIds: params.signals.map((signal) => signal.id),
    riskScore,
    riskBreakdown: {
      signalWeight: riskScore,
      signalCount: params.signals.length
    },
    stage: params.stage,
    status: "planned",
    reason: `${params.signals.length} signal(s): ${slugs.join(", ")}`
  };
}

export function createFinding(params: {
  projectId: string;
  runId: string;
  primaryAssetId: string;
  relatedAssetIds?: string[];
  title: string;
  category: string;
  cwe?: string[];
  severity: Severity;
  confidence: Confidence;
  evidenceLevel: EvidenceLevel;
  summary: string;
  technicalDetails: string;
  impact: string;
  recommendation: string;
  assumptions?: string[];
  negativeEvidence?: string[];
  lineNumbers?: number[];
  producedBy: Finding["producedBy"];
}): Finding {
  const fingerprint = makeId("finding", [
    params.projectId,
    params.primaryAssetId,
    params.category,
    params.title,
    params.lineNumbers ?? []
  ]);
  return {
    id: fingerprint,
    projectId: params.projectId,
    firstRunId: params.runId,
    latestRunId: params.runId,
    primaryAssetId: params.primaryAssetId,
    relatedAssetIds: params.relatedAssetIds ?? [],
    title: params.title,
    category: params.category,
    cwe: params.cwe ?? [],
    severity: params.severity,
    confidence: params.confidence,
    evidenceLevel: params.evidenceLevel,
    summary: params.summary,
    technicalDetails: params.technicalDetails,
    impact: params.impact,
    recommendation: params.recommendation,
    assumptions: params.assumptions ?? [],
    negativeEvidence: params.negativeEvidence ?? [],
    lineNumbers: params.lineNumbers ?? [],
    fingerprint,
    status: "open",
    producedBy: params.producedBy,
    createdAt: nowIso(),
    updatedAt: nowIso()
  };
}

export function createEvidence(params: {
  runId: string;
  projectId: string;
  findingId?: string;
  candidateId?: string;
  assetId?: string;
  kind: EvidenceItem["kind"];
  source: string;
  summary: string;
  locator?: string;
  startLine?: number;
  endLine?: number;
  raw?: unknown;
}): EvidenceItem {
  return {
    id: makeId("evidence", [
      params.runId,
      params.findingId,
      params.candidateId,
      params.assetId,
      params.kind,
      params.source,
      params.summary
    ]),
    findingId: params.findingId,
    candidateId: params.candidateId,
    runId: params.runId,
    projectId: params.projectId,
    assetId: params.assetId,
    kind: params.kind,
    source: params.source,
    summary: params.summary,
    locator: params.locator,
    startLine: params.startLine,
    endLine: params.endLine,
    raw: params.raw,
    createdAt: nowIso()
  };
}

export function createValidation(params: {
  findingId: string;
  runId: string;
  validatorKind: string;
  axes: Pick<ValidationVerdict, "real" | "reachable" | "impactful" | "general">;
  fixed?: AxisVerdict;
  model?: string;
  adjustedSeverity?: Severity;
  adjustedEvidenceLevel?: EvidenceLevel;
  reasoningSummary: string;
  counterArgument?: string;
  requiredFollowup?: string[];
}): ValidationVerdict {
  return {
    id: makeId("validation", [params.findingId, params.runId, params.validatorKind]),
    findingId: params.findingId,
    runId: params.runId,
    validatorKind: params.validatorKind,
    model: params.model,
    real: params.axes.real,
    reachable: params.axes.reachable,
    impactful: params.axes.impactful,
    general: params.axes.general,
    fixed: params.fixed,
    adjustedSeverity: params.adjustedSeverity,
    adjustedEvidenceLevel: params.adjustedEvidenceLevel,
    reasoningSummary: params.reasoningSummary,
    counterArgument: params.counterArgument ?? "",
    requiredFollowup: params.requiredFollowup ?? [],
    createdAt: nowIso()
  };
}

export class JsonEvidenceStore {
  readonly dataPath: string;
  data: StoreData;

  constructor(readonly rootPath: string, config: ProofstrikeConfig = DEFAULT_CONFIG) {
    this.dataPath = path.resolve(rootPath, config.dataPath || DEFAULT_CONFIG.dataPath);
    this.data = readJsonIfExists<StoreData>(this.dataPath, createEmptyStore());
    this.data.fileStates ??= [];
    this.data.modelUsage ??= [];
  }

  createRun(run: RunRecord): void {
    this.data.runs.push(run);
    this.flush();
  }

  completeRun(runId: string, patch: Partial<RunRecord> = {}): void {
    const run = this.data.runs.find((item) => item.id === runId);
    if (!run) throw new Error(`Run not found: ${runId}`);
    Object.assign(run, patch, { status: patch.status ?? "done", completedAt: nowIso() });
    run.stats = this.statsForRun(runId);
    this.flush();
  }

  upsertAssets(assets: AssetRecord[]): void {
    for (const asset of assets) upsertById(this.data.assets, asset);
    this.flush();
  }

  updateFileStates(params: { projectId: string; runId: string; files: AssetRecord[]; markDeleted?: boolean }): void {
    const seen = new Set<string>();
    for (const asset of params.files) {
      if (!asset.filePath) continue;
      seen.add(asset.filePath);
      const existing = this.data.fileStates.find((item) =>
        item.projectId === params.projectId && item.filePath === asset.filePath
      );
      const next: FileStateRecord = {
        id: existing?.id ?? makeId("filestate", [params.projectId, asset.filePath]),
        projectId: params.projectId,
        filePath: asset.filePath,
        language: asset.language,
        hash: stringValue(asset.metadata.hash),
        bytes: numberValue(asset.metadata.bytes),
        lines: numberValue(asset.metadata.lines),
        firstSeenRunId: existing?.firstSeenRunId ?? params.runId,
        lastSeenRunId: params.runId,
        status: "active",
        updatedAt: nowIso()
      };
      upsertById(this.data.fileStates, next);
    }
    for (const state of this.data.fileStates.filter((item) => item.projectId === params.projectId)) {
      if (params.markDeleted && !seen.has(state.filePath) && state.status === "active") {
        state.status = "deleted";
        state.updatedAt = nowIso();
      }
    }
    this.flush();
  }

  appendSignals(signals: Signal[]): void {
    for (const signal of signals) upsertById(this.data.signals, signal);
    this.flush();
  }

  upsertCandidates(candidates: Candidate[]): void {
    for (const candidate of candidates) upsertById(this.data.candidates, candidate);
    this.flush();
  }

  writeWorkPackets(packets: WorkPacket[]): void {
    for (const packet of packets) upsertById(this.data.workPackets, packet);
    this.flush();
  }

  updateWorkPacket(packetId: string, patch: Partial<WorkPacket>): void {
    const packet = this.data.workPackets.find((item) => item.id === packetId);
    if (!packet) throw new Error(`Work packet not found: ${packetId}`);
    Object.assign(packet, patch);
    this.flush();
  }

  appendFindings(findings: Finding[]): void {
    for (const finding of findings) upsertById(this.data.findings, finding);
    this.flush();
  }

  appendEvidence(items: EvidenceItem[]): void {
    for (const item of items) upsertById(this.data.evidenceItems, item);
    this.flush();
  }

  appendValidations(validations: ValidationVerdict[]): void {
    for (const validation of validations) upsertById(this.data.validations, validation);
    this.flush();
  }

  appendPolicyDecisions(decisions: PolicyEvaluation[]): void {
    for (const decision of decisions) upsertById(this.data.policyDecisions, decision);
    this.flush();
  }

  appendModelUsage(records: ModelUsageRecord[]): void {
    for (const record of records) upsertById(this.data.modelUsage, record);
    this.flush();
  }

  writeRunArtifact(runId: string, name: string, artifact: unknown): string {
    const safeName = name.replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "") || "artifact";
    const artifactPath = path.resolve(path.dirname(this.dataPath), "artifacts", runId, `${safeName}.json`);
    writeJson(artifactPath, artifact);
    return artifactPath;
  }

  recordRunError(runId: string, error: unknown): void {
    const run = this.data.runs.find((item) => item.id === runId);
    if (!run) throw new Error(`Run not found: ${runId}`);
    run.errors.push(error instanceof Error ? error.message : String(error));
    this.flush();
  }

  getRun(runId: string): RunRecord | undefined {
    return this.data.runs.find((run) => run.id === runId);
  }

  latestRun(projectId: string): RunRecord | undefined {
    return [...this.data.runs].reverse().find((run) => run.projectId === projectId);
  }

  getProjectHistory(projectId: string): ProjectHistorySummary {
    const findings = this.data.findings.filter((finding) => finding.projectId === projectId);
    return {
      findingCount: findings.length,
      openFindings: findings.filter((finding) => finding.status === "open").length,
      categories: countBy(findings, (finding) => finding.category),
      recentFindings: findings.slice(-20)
    };
  }

  queryRun(runId: string): RunQuery {
    return {
      run: this.getRun(runId),
      assets: this.data.assets.filter((item) => item.lastSeenRunId === runId || item.firstSeenRunId === runId),
      signals: this.data.signals.filter((item) => item.runId === runId),
      candidates: this.data.candidates.filter((item) => item.runId === runId),
      workPackets: this.data.workPackets.filter((item) => item.runId === runId),
      findings: this.data.findings.filter((item) => item.latestRunId === runId || item.firstRunId === runId),
      evidenceItems: this.data.evidenceItems.filter((item) => item.runId === runId),
      validations: this.data.validations.filter((item) => item.runId === runId),
      policyDecisions: this.data.policyDecisions.filter((item) => item.runId === runId)
    };
  }

  statsForRun(runId: string): Record<string, number> {
    const query = this.queryRun(runId);
    return {
      assets: query.assets.length,
      signals: query.signals.length,
      candidates: query.candidates.length,
      workPackets: query.workPackets.length,
      findings: query.findings.length,
      validations: query.validations.length,
      modelUsage: this.data.modelUsage.filter((item) => item.runId === runId).length,
      fileStates: this.data.fileStates.filter((item) => item.lastSeenRunId === runId).length
    };
  }

  flush(): void {
    writeJson(this.dataPath, this.data);
  }
}

export interface ProjectHistorySummary {
  findingCount: number;
  openFindings: number;
  categories: Record<string, number>;
  recentFindings: Finding[];
}

export interface RunQuery {
  run?: RunRecord;
  assets: AssetRecord[];
  signals: Signal[];
  candidates: Candidate[];
  workPackets: WorkPacket[];
  findings: Finding[];
  evidenceItems: EvidenceItem[];
  validations: ValidationVerdict[];
  policyDecisions: PolicyEvaluation[];
}

export function createEmptyStore(): StoreData {
  return {
    schemaVersion: 1,
    runs: [],
    assets: [],
    signals: [],
    candidates: [],
    workPackets: [],
    findings: [],
    evidenceItems: [],
    validations: [],
    policyDecisions: [],
    suppressions: [],
    packVersions: [],
    modelUsage: [],
    fileStates: []
  };
}

export function evaluatePolicy(params: {
  findings: Finding[];
  validations: ValidationVerdict[];
  config: ProofstrikeConfig;
  assets?: AssetRecord[];
}): PolicyEvaluation[] {
  return params.findings.map((finding) => {
    const validation = params.validations.find((item) => item.findingId === finding.id);
    const asset = params.assets?.find((item) => item.id === finding.primaryAssetId);
    const suppression = matchingSuppression(finding, params.config.suppressions ?? [], asset);
    const decision = suppression
      ? decisionForSuppression(suppression)
      : decisionForFinding(finding, validation, params.config, asset);
    return {
      id: makeId("policy", [finding.id, decision.decision, decision.reason]),
      runId: finding.latestRunId,
      findingId: finding.id,
      ...decision,
      createdAt: nowIso()
    };
  });
}

export function decisionForFinding(
  finding: Finding,
  validation?: ValidationVerdict,
  config: Pick<ProofstrikeConfig, "failOn" | "manualReviewOn"> = DEFAULT_CONFIG,
  asset?: AssetRecord
): Omit<PolicyEvaluation, "id" | "runId" | "findingId" | "createdAt"> {
  const real = validation?.real?.passed === true;
  const severityRank = SEVERITIES.indexOf(finding.severity);
  if (finding.status === "suppressed" || finding.status === "accepted_risk") {
    return { decision: "pass", reason: `Finding is ${finding.status}.`, ruleId: "status" };
  }
  const failRule = firstMatchingRule(config.failOn ?? [], finding, validation, asset);
  if (failRule) {
    return {
      decision: normalizeDecision(failRule.decision, "fail"),
      reason: stringValue(failRule.reason) ?? `Matched configured failOn rule ${stringValue(failRule.id) ?? "unnamed"}.`,
      ruleId: stringValue(failRule.id) ?? "config-failOn"
    };
  }
  const reviewRule = firstMatchingRule(config.manualReviewOn ?? [], finding, validation, asset);
  if (reviewRule) {
    return {
      decision: normalizeDecision(reviewRule.decision, "manual_review"),
      reason: stringValue(reviewRule.reason) ?? `Matched configured manualReviewOn rule ${stringValue(reviewRule.id) ?? "unnamed"}.`,
      ruleId: stringValue(reviewRule.id) ?? "config-manualReviewOn"
    };
  }
  if (finding.category === "secrets" && finding.confidence === "high") {
    return { decision: "fail", reason: "High-confidence secret exposure.", ruleId: "default-secret" };
  }
  if (severityRank >= SEVERITIES.indexOf("critical") && real) {
    return { decision: "fail", reason: "Validated critical finding.", ruleId: "default-critical" };
  }
  if (severityRank >= SEVERITIES.indexOf("high") && real) {
    return { decision: "manual_review", reason: "Validated high-severity finding.", ruleId: "default-high-review" };
  }
  if (!validation || validation.real?.passed === "unknown") {
    return { decision: "warn", reason: "Finding needs validation.", ruleId: "default-uncertain" };
  }
  if (validation.real?.passed === false) {
    return { decision: "pass", reason: "Validator marked finding as likely false positive.", ruleId: "default-false-positive" };
  }
  return { decision: "warn", reason: "Finding is real but below blocking threshold.", ruleId: "default-warn" };
}

export function policyRuleMatchesFinding(
  rule: PolicyRule,
  finding: Finding,
  validation?: ValidationVerdict,
  asset?: AssetRecord
): boolean {
  if (rule.severity && !severityAtLeast(finding.severity, rule.severity)) return false;
  if (rule.minSeverity && !severityAtLeast(finding.severity, rule.minSeverity)) return false;
  if (rule.category && !matchesStringSet(finding.category, rule.category)) return false;
  if (rule.confidence && finding.confidence !== rule.confidence) return false;
  if (rule.minConfidence && !confidenceAtLeast(finding.confidence, rule.minConfidence)) return false;
  if (rule.evidenceAtLeast && !evidenceAtLeast(finding.evidenceLevel, rule.evidenceAtLeast)) return false;
  if (rule.status && !matchesStringSet(finding.status, rule.status)) return false;
  if (rule.path && !matchesPath(asset?.filePath ?? asset?.locator ?? "", rule.path)) return false;
  if (rule.validation && !matchesValidation(rule.validation, validation)) return false;
  return true;
}

export function matchingSuppression(
  finding: Finding,
  suppressions: SuppressionRule[],
  asset?: AssetRecord
): SuppressionRule | undefined {
  return suppressions.find((suppression) => {
    if (!isSuppressionActive(suppression)) return false;
    if (suppression.findingId && suppression.findingId !== finding.id) return false;
    if (suppression.fingerprint && suppression.fingerprint !== finding.fingerprint) return false;
    if (suppression.category && !matchesStringSet(finding.category, suppression.category)) return false;
    if (suppression.path && !matchesPath(asset?.filePath ?? asset?.locator ?? "", suppression.path)) return false;
    return Boolean(suppression.findingId || suppression.fingerprint || suppression.category || suppression.path);
  });
}

export function isSuppressionActive(suppression: SuppressionRule, now = new Date()): boolean {
  if (!suppression.expiresAt) return true;
  const expires = Date.parse(suppression.expiresAt);
  return !Number.isNaN(expires) && expires >= now.getTime();
}

function decisionForSuppression(
  suppression: SuppressionRule
): Omit<PolicyEvaluation, "id" | "runId" | "findingId" | "createdAt"> {
  const status = suppression.status ?? "suppressed";
  return {
    decision: "pass",
    reason: suppression.reason ? `${status}: ${suppression.reason}` : `Finding is ${status} by config suppression.`,
    ruleId: suppression.id ?? `suppression:${status}`
  };
}

function firstMatchingRule(
  rules: PolicyRule[],
  finding: Finding,
  validation?: ValidationVerdict,
  asset?: AssetRecord
): PolicyRule | undefined {
  return rules.find((rule) => policyRuleMatchesFinding(rule, finding, validation, asset));
}

function normalizeDecision(value: unknown, fallback: PolicyDecision): PolicyDecision {
  return typeof value === "string" && (POLICY_DECISIONS as readonly string[]).includes(value)
    ? value as PolicyDecision
    : fallback;
}

function severityAtLeast(actual: Severity, minimum: Severity): boolean {
  return SEVERITIES.indexOf(actual) >= SEVERITIES.indexOf(minimum);
}

function confidenceAtLeast(actual: Confidence, minimum: Confidence): boolean {
  return CONFIDENCES.indexOf(actual) >= CONFIDENCES.indexOf(minimum);
}

function evidenceAtLeast(actual: EvidenceLevel, minimum: EvidenceLevel): boolean {
  return EVIDENCE_LEVELS.indexOf(actual) >= EVIDENCE_LEVELS.indexOf(minimum);
}

function matchesStringSet(actual: string, expected: string | string[]): boolean {
  return Array.isArray(expected) ? expected.includes(actual) : actual === expected;
}

function matchesValidation(rule: NonNullable<PolicyRule["validation"]>, validation?: ValidationVerdict): boolean {
  if (rule === "none") return !validation;
  if (rule === "unknown") return !validation || validation.real.passed === "unknown";
  return validation?.[rule]?.passed === true;
}

function matchesPath(actualPath: string, pattern: string): boolean {
  if (!actualPath) return false;
  const normalizedPath = normalizePath(actualPath);
  const normalizedPattern = normalizePath(pattern);
  const escaped = normalizedPattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "__PROOFSTRIKE_GLOBSTAR__")
    .replace(/\*/g, "[^/]*");
  return new RegExp(`^${escaped.replace(/__PROOFSTRIKE_GLOBSTAR__/g, ".*")}$`).test(normalizedPath);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function upsertById<T extends { id: string }>(list: T[], item: T): void {
  const index = list.findIndex((existing) => existing.id === item.id);
  if (index >= 0) list[index] = { ...list[index], ...item };
  else list.push(item);
}

function countBy<T>(items: T[], fn: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const key = fn(item);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}
