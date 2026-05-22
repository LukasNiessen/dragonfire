import {
  type AssetRecord,
  type Candidate,
  type EvidenceItem,
  type Finding,
  type ModelUsageRecord,
  type PolicyEvaluation,
  type ProofstrikeConfig,
  type Signal,
  type StageName,
  type ValidationVerdict,
  type WorkPacket,
  JsonEvidenceStore,
  createCandidate,
  createEvidence,
  createRun,
  createSignal,
  evaluatePolicy,
  makeId,
  nowIso
} from "../../core/src/index.js";
import fs from "node:fs";
import path from "node:path";
import { type ArtifactSnapshot, RepositoryIngestor } from "../../ingest/src/index.js";
import { MatcherEngine } from "../../scanner/src/index.js";
import { loadMatcherPackRefs } from "../../scanner/src/custom.js";
import { type CodeIndex, CodeIndexer, GraphExpander, graphSummaryForPacket } from "../../graph/src/index.js";
import { KnowledgeRouter } from "../../knowledge/src/index.js";
import { EnrichmentEngine } from "../../enrichment/src/index.js";
import { ExtensionRegistry, type NotificationRecord } from "../../extensions/src/index.js";
import { AgentRuntime, createAgentRuntimeFromConfig } from "../../agents/src/index.js";
import { type ReviewEvent, type StagePlan, StageResolver } from "../../stages/src/index.js";
import { collectExternalToolSignals } from "../../tools/src/index.js";
import picomatch from "picomatch";

export interface ReviewParams {
  rootPath: string;
  config: ProofstrikeConfig;
  stage?: StageName;
  event?: ReviewEvent;
  diffBase?: string;
  explicitFiles?: string[];
  store?: JsonEvidenceStore;
}

export interface ResumeParams {
  rootPath: string;
  config: ProofstrikeConfig;
  runId?: string;
  store?: JsonEvidenceStore;
}

export interface ReviewResult {
  runId: string;
  stagePlan: StagePlan;
  snapshot: ArtifactSnapshot;
  codeIndex: CodeIndex;
  assets: AssetRecord[];
  signals: Signal[];
  candidates: Candidate[];
  workPackets: WorkPacket[];
  findings: Finding[];
  evidence: EvidenceItem[];
  validations: ValidationVerdict[];
  policyDecisions: PolicyEvaluation[];
  notifications: NotificationRecord[];
  store: JsonEvidenceStore;
}

export interface RevalidateResult {
  runId: string;
  checked: number;
  fixed: number;
  stillOpen: number;
  findings: Finding[];
  validations: ValidationVerdict[];
}

interface PacketExecutionResult {
  packet: WorkPacket;
  findings: Finding[];
  evidence: EvidenceItem[];
  validations: ValidationVerdict[];
}

export class ReviewRunner {
  static withExtensions(extensions: ExtensionRegistry, agentRuntime = new AgentRuntime()): ReviewRunner {
    return new ReviewRunner(
      new StageResolver(),
      new RepositoryIngestor(),
      new CodeIndexer(),
      new MatcherEngine(),
      new GraphExpander(),
      new KnowledgeRouter(),
      extensions,
      agentRuntime
    );
  }

  constructor(
    private readonly stageResolver = new StageResolver(),
    private readonly ingestor = new RepositoryIngestor(),
    private readonly indexer = new CodeIndexer(),
    private readonly matcherEngine = new MatcherEngine(),
    private readonly graphExpander = new GraphExpander(),
    private readonly knowledgeRouter = new KnowledgeRouter(),
    private readonly extensions = new ExtensionRegistry(),
    private readonly agentRuntime = new AgentRuntime()
  ) {}

  async run(params: ReviewParams): Promise<ReviewResult> {
    const { rootPath, config, event = {}, diffBase, explicitFiles = [] } = params;
    const store = params.store ?? new JsonEvidenceStore(rootPath, config);
    const history = store.getProjectHistory(config.projectId);
    const stagePlan = this.stageResolver.resolve({
      event,
      config,
      history,
      cliOverrides: { stage: params.stage }
    });
    if (config.runtime?.directDiffOnly && !diffBase && explicitFiles.length === 0) {
      throw new Error("runtime.directDiffOnly is enabled, but no --diff or --files scope was provided.");
    }
    const run = createRun({
      projectId: config.projectId,
      rootPath,
      stage: stagePlan.name,
      eventType: event.type || "manual",
      scope: {
        diffBase,
        explicitFiles,
        directDiffOnly: Boolean(config.runtime?.directDiffOnly)
      },
      metadata: {
        maxConcurrency: config.runtime?.maxConcurrency ?? 1,
        retries: config.runtime?.retries ?? 0,
        externalTools: stagePlan.tools.external
      }
    });
    store.createRun(run);

    try {
      const snapshot = await this.ingestor.ingest({
        rootPath,
        runId: run.id,
        projectId: config.projectId,
        stagePlan,
        diffBase,
        explicitFiles,
        config
      });
      const codeIndex = await this.indexer.index(snapshot);
      const assets: AssetRecord[] = [...snapshot.files, ...codeIndex.routes];
      store.upsertAssets(assets);
      store.updateFileStates({
        projectId: config.projectId,
        runId: run.id,
        files: snapshot.files,
        markDeleted: snapshot.scopedFileCount === snapshot.allFileCount
      });
      store.writeRunArtifact(run.id, "snapshot", snapshot);
      store.writeRunArtifact(run.id, "code-index", codeIndex);
      const enrichment = await new EnrichmentEngine(this.extensions.ownership()).collect({ snapshot, assets });
      store.appendEvidence(enrichment.evidence);
      const additionalMatchers = [
        ...loadMatcherPackRefs(rootPath, config.packs ?? []),
        ...this.extensions.matchers()
      ];

      const signals = [
        ...createHotspotSignals(snapshot),
        ...await this.matcherEngine.run({ snapshot, stagePlan, additionalMatchers }),
        ...await collectExternalToolSignals({
          snapshot,
          stagePlan,
          outputDir: path.resolve(rootPath, config.outputDir || ".proofstrike/reports", "artifacts")
        })
      ];
      signals.push(...createScopeReviewSignals({ snapshot, stagePlan, existingSignals: signals }));
      store.appendSignals(signals);
      store.writeRunArtifact(run.id, "signals", signals);

      const candidates = this.buildCandidates({ snapshot, signals, stagePlan });
      const expanded = this.graphExpander.expandCandidates({ candidates, codeIndex, stagePlan });
      store.upsertCandidates(expanded);
      store.writeRunArtifact(run.id, "candidates", expanded);

      const workPackets = this.planWorkPackets({ snapshot, candidates: expanded, signals, stagePlan });
      store.writeWorkPackets(workPackets);
      store.writeRunArtifact(run.id, "work-packets", workPackets);

      const packetResults = await this.runWorkPackets({
        rootPath,
        config,
        store,
        snapshot,
        codeIndex,
        assets,
        signals,
        stagePlan,
        workPackets
      });
      const allFindings = packetResults.flatMap((result) => result.findings);
      const allEvidence = [...enrichment.evidence, ...packetResults.flatMap((result) => result.evidence)];
      const allValidations = packetResults.flatMap((result) => result.validations);
      const policyDecisions = evaluatePolicy({ findings: allFindings, validations: allValidations, config, assets });
      store.appendPolicyDecisions(policyDecisions);
      const notifications = await this.notifyFindings({
        rootPath,
        config,
        findings: allFindings,
        policyDecisions
      });
      store.writeRunArtifact(run.id, "findings", allFindings);
      store.writeRunArtifact(run.id, "validations", allValidations);
      store.writeRunArtifact(run.id, "policy-decisions", policyDecisions);
      store.writeRunArtifact(run.id, "notifications", notifications);
      store.completeRun(run.id, { status: policyDecisions.some((item) => item.decision === "fail") ? "failed_policy" : "done" });
      return {
        runId: run.id,
        stagePlan,
        snapshot,
        codeIndex,
        assets,
        signals,
        candidates: expanded,
        workPackets,
        findings: allFindings,
        evidence: allEvidence,
        validations: allValidations,
        policyDecisions,
        notifications,
        store
      };
    } catch (error) {
      store.completeRun(run.id, {
        status: "error",
        errors: [error instanceof Error ? error.message : String(error)]
      });
      throw error;
    }
  }

  async resume(params: ResumeParams): Promise<ReviewResult> {
    const store = params.store ?? new JsonEvidenceStore(params.rootPath, params.config);
    const run = params.runId
      ? store.getRun(params.runId)
      : [...store.data.runs].reverse().find((item) =>
          item.projectId === params.config.projectId && (item.status === "running" || item.status === "error")
        );
    if (!run) throw new Error("No resumable Proofstrike run found.");
    const stagePlan = this.stageResolver.resolve({
      config: params.config,
      event: { type: run.eventType, stage: run.stage },
      cliOverrides: { stage: run.stage }
    });
    const remainingPackets = store.data.workPackets
      .filter((packet) => packet.runId === run.id && packet.status !== "done" && packet.status !== "cancelled")
      .map((packet) => ({ ...packet, status: "queued" as const }));
    store.writeWorkPackets(remainingPackets);
    const filePaths = Array.from(new Set(remainingPackets
      .flatMap((packet) => packet.assetIds)
      .map((assetId) => store.data.assets.find((asset) => asset.id === assetId)?.filePath)
      .filter((filePath): filePath is string => Boolean(filePath))));
    const snapshot = await this.ingestor.ingest({
      rootPath: params.rootPath,
      runId: run.id,
      projectId: params.config.projectId,
      stagePlan,
      explicitFiles: filePaths,
      config: params.config
    });
    const codeIndex = await this.indexer.index(snapshot);
    const assets: AssetRecord[] = [...snapshot.files, ...codeIndex.routes];
    store.upsertAssets(assets);
    store.updateFileStates({ projectId: params.config.projectId, runId: run.id, files: snapshot.files });
    const signals = store.data.signals.filter((signal) => signal.runId === run.id);
    const candidates = store.data.candidates.filter((candidate) => candidate.runId === run.id);

    await this.runWorkPackets({
      rootPath: params.rootPath,
      config: params.config,
      store,
      snapshot,
      codeIndex,
      assets,
      signals,
      stagePlan,
      workPackets: remainingPackets
    });

    const query = store.queryRun(run.id);
    const policyDecisions = evaluatePolicy({
      findings: query.findings,
      validations: query.validations,
      config: params.config,
      assets
    });
    store.appendPolicyDecisions(policyDecisions);
    store.completeRun(run.id, { status: policyDecisions.some((item) => item.decision === "fail") ? "failed_policy" : "done" });
    return {
      runId: run.id,
      stagePlan,
      snapshot,
      codeIndex,
      assets,
      signals,
      candidates,
      workPackets: store.data.workPackets.filter((packet) => packet.runId === run.id),
      findings: query.findings,
      evidence: query.evidenceItems,
      validations: query.validations,
      policyDecisions,
      notifications: [],
      store
    };
  }

  private async notifyFindings(params: {
    rootPath: string;
    config: ProofstrikeConfig;
    findings: Finding[];
    policyDecisions: PolicyEvaluation[];
  }): Promise<NotificationRecord[]> {
    const records: NotificationRecord[] = [];
    const notifiers = this.extensions.notifiers();
    if (notifiers.length === 0) return records;
    for (const finding of params.findings) {
      const policy = params.policyDecisions.find((item) => item.findingId === finding.id);
      if (policy?.decision !== "fail" && policy?.decision !== "manual_review") continue;
      for (const notifier of notifiers) {
        records.push(await notifier.notify({
          finding,
          policy,
          projectId: params.config.projectId,
          rootPath: params.rootPath
        }));
      }
    }
    return records;
  }

  private async runWorkPackets(params: {
    rootPath: string;
    config: ProofstrikeConfig;
    store: JsonEvidenceStore;
    snapshot: ArtifactSnapshot;
    codeIndex: CodeIndex;
    assets: AssetRecord[];
    signals: Signal[];
    stagePlan: StagePlan;
    workPackets: WorkPacket[];
  }): Promise<PacketExecutionResult[]> {
    const maxConcurrency = Math.max(1, Math.min(16, Number(params.config.runtime?.maxConcurrency ?? 1)));
    const results: PacketExecutionResult[] = [];
    let nextIndex = 0;
    const workers = Array.from({ length: Math.min(maxConcurrency, params.workPackets.length || 1) }, async () => {
      while (nextIndex < params.workPackets.length) {
        const packet = params.workPackets[nextIndex]!;
        nextIndex += 1;
        const result = await this.runPacketWithRetry({ ...params, packet });
        results.push(result);
      }
    });
    await Promise.all(workers);
    return results.sort((a, b) => a.packet.id.localeCompare(b.packet.id));
  }

  private async runPacketWithRetry(params: {
    rootPath: string;
    config: ProofstrikeConfig;
    store: JsonEvidenceStore;
    snapshot: ArtifactSnapshot;
    codeIndex: CodeIndex;
    assets: AssetRecord[];
    signals: Signal[];
    stagePlan: StagePlan;
    packet: WorkPacket;
  }): Promise<PacketExecutionResult> {
    const retries = Math.max(0, Number(params.config.runtime?.retries ?? 0));
    let lastError: unknown;
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      let lock: PacketLock | undefined;
      try {
        lock = PacketLock.acquire(params.rootPath, params.packet.id, params.config.runtime?.staleLockMs);
        params.store.updateWorkPacket(params.packet.id, { status: "running" });
        const result = await this.executePacket(params);
        params.store.appendFindings(result.findings);
        params.store.appendEvidence(result.evidence);
        params.store.appendValidations(result.validations);
        params.store.updateWorkPacket(params.packet.id, { status: "done" });
        return result;
      } catch (error) {
        lastError = error;
        params.store.recordRunError(params.packet.runId, `Packet ${params.packet.id} attempt ${attempt + 1} failed: ${errorMessage(error)}`);
        if (attempt >= retries) {
          params.store.updateWorkPacket(params.packet.id, { status: "error" });
          throw new Error(`Work packet ${params.packet.id} failed after ${attempt + 1} attempt(s): ${errorMessage(error)}`);
        }
      } finally {
        lock?.release();
      }
    }
    throw new Error(`Work packet ${params.packet.id} failed: ${errorMessage(lastError)}`);
  }

  private async executePacket(params: {
    rootPath: string;
    config: ProofstrikeConfig;
    store: JsonEvidenceStore;
    snapshot: ArtifactSnapshot;
    codeIndex: CodeIndex;
    assets: AssetRecord[];
    signals: Signal[];
    stagePlan: StagePlan;
    packet: WorkPacket;
  }): Promise<PacketExecutionResult> {
    const agentRuntime = createAgentRuntimeFromConfig(params.config, this.agentRuntime);
    const packetSignals = params.signals.filter((signal) => params.packet.signalIds.includes(signal.id));
    const packetAssets = params.assets.filter((asset) => params.packet.assetIds.includes(asset.id));
    const knowledgeSelection = this.knowledgeRouter.select({
      workPacket: params.packet,
      signals: packetSignals,
      snapshot: params.snapshot,
      stagePlan: params.stagePlan
    });
    const renderedKnowledge = this.knowledgeRouter.render(knowledgeSelection, params.snapshot.instructions);
    const output = await agentRuntime.investigate({
      workPacket: params.packet,
      snapshot: params.snapshot,
      assets: packetAssets,
      signals: packetSignals,
      renderedKnowledge,
      graphSummary: graphSummaryForPacket(params.packet, params.codeIndex)
    });
    const validations: ValidationVerdict[] = [];
    for (const finding of output.findings) {
      if (!params.stagePlan.validators.enabled) continue;
      const validation = await agentRuntime.validate({
        finding,
        snapshot: params.snapshot,
        assets: packetAssets,
        evidence: output.evidence.filter((item) => item.findingId === finding.id)
      });
      validations.push(validation);
    }
    appendUsageWithBudget(params.store, params.packet.runId, agentRuntime.drainUsage(), params.stagePlan.maxCostUsd);
    return {
      packet: params.packet,
      findings: output.findings,
      evidence: output.evidence,
      validations
    };
  }

  buildCandidates(params: { snapshot: ArtifactSnapshot; signals: Signal[]; stagePlan: StagePlan }): Candidate[] {
    const byAsset = new Map<string, Signal[]>();
    for (const signal of params.signals) {
      const current = byAsset.get(signal.assetId) ?? [];
      current.push(signal);
      byAsset.set(signal.assetId, current);
    }
    return [...byAsset.entries()].map(([assetId, assetSignals]) => createCandidate({
      runId: params.snapshot.runId,
      projectId: params.snapshot.projectId,
      primaryAssetId: assetId,
      relatedAssetIds: [],
      signals: assetSignals,
      stage: params.stagePlan.name
    }));
  }

  planWorkPackets(params: {
    snapshot: ArtifactSnapshot;
    candidates: Candidate[];
    signals: Signal[];
    stagePlan: StagePlan;
  }): WorkPacket[] {
    const maxPackets = params.stagePlan.maxWorkPackets === "unlimited"
      ? params.candidates.length
      : Number(params.stagePlan.maxWorkPackets || params.candidates.length);
    return params.candidates
      .sort((a, b) => b.riskScore - a.riskScore || a.primaryAssetId.localeCompare(b.primaryAssetId))
      .slice(0, maxPackets)
      .map((candidate) => ({
        id: makeId("packet", [params.snapshot.runId, candidate.id]),
        runId: params.snapshot.runId,
        projectId: params.snapshot.projectId,
        stage: params.stagePlan.name,
        agentKind: "static-investigator",
        primaryAssetId: candidate.primaryAssetId,
        assetIds: candidate.relatedAssetIds,
        candidateIds: [candidate.id],
        signalIds: params.signals.filter((signal) => candidate.signalIds.includes(signal.id)).map((signal) => signal.id),
        codeContext: [],
        graphContext: [],
        knowledgePackIds: [],
        projectInstructionIds: params.snapshot.instructions.map((instruction) => instruction.path),
        historyRefs: [],
        budget: {
          maxCostUsd: params.stagePlan.maxCostUsd,
          maxPromptChars: params.stagePlan.name === "pull_request" ? 12000 : 32000
        },
        outputSchema: "finding_array",
        status: "queued"
      }));
  }
}

export class RevalidationRunner {
  constructor(
    private readonly stageResolver = new StageResolver(),
    private readonly ingestor = new RepositoryIngestor(),
    private readonly matcherEngine = new MatcherEngine(),
    private readonly agentRuntime = new AgentRuntime()
  ) {}

  async run(params: { rootPath: string; config: ProofstrikeConfig; store?: JsonEvidenceStore }): Promise<RevalidateResult> {
    const store = params.store ?? new JsonEvidenceStore(params.rootPath, params.config);
    const openFindings = store.data.findings.filter((finding) => finding.projectId === params.config.projectId && finding.status === "open");
    const stagePlan = this.stageResolver.resolve({
      config: params.config,
      event: { type: "revalidate" },
      cliOverrides: { stage: "campaign" }
    });
    const run = createRun({
      projectId: params.config.projectId,
      rootPath: params.rootPath,
      stage: stagePlan.name,
      eventType: "revalidate"
    });
    store.createRun(run);

    const filePaths = Array.from(new Set(openFindings
      .map((finding) => store.data.assets.find((item) => item.id === finding.primaryAssetId)?.filePath)
      .filter((filePath): filePath is string => Boolean(filePath))
      .filter((filePath) => fs.existsSync(path.join(params.rootPath, filePath)))));
    const currentSignalsByAsset = new Map<string, Signal[]>();
    if (filePaths.length > 0) {
      const snapshot = await this.ingestor.ingest({
        rootPath: params.rootPath,
        runId: run.id,
        projectId: params.config.projectId,
        stagePlan,
        explicitFiles: filePaths,
        config: params.config
      });
      store.updateFileStates({ projectId: params.config.projectId, runId: run.id, files: snapshot.files });
      const signals = await this.matcherEngine.run({
        snapshot,
        stagePlan,
        additionalMatchers: loadMatcherPackRefs(params.rootPath, params.config.packs ?? [])
      });
      store.appendSignals(signals);
      for (const signal of signals) {
        const current = currentSignalsByAsset.get(signal.assetId) ?? [];
        current.push(signal);
        currentSignalsByAsset.set(signal.assetId, current);
      }
    }

    let fixed = 0;
    let stillOpen = 0;
    const validations: ValidationVerdict[] = [];
    for (const finding of openFindings) {
      const asset = store.data.assets.find((item) => item.id === finding.primaryAssetId);
      if (!asset?.filePath) {
        markFindingFixed(finding, run.id);
        fixed += 1;
        continue;
      }
      const absolute = path.join(params.rootPath, asset.filePath);
      const exists = fs.existsSync(absolute);
      if (!exists) {
        markFindingFixed(finding, run.id);
        fixed += 1;
        continue;
      }
      const currentSignals = currentSignalsByAsset.get(asset.id) ?? [];
      const stillHasSignal = findingStillHasSignal({ finding, currentSignals, store });
      const revalidationEvidence = createRevalidationEvidence({
        runId: run.id,
        projectId: params.config.projectId,
        finding,
        asset,
        stillHasSignal,
        currentSignals
      });
      store.appendEvidence(revalidationEvidence);
      const snapshotForValidation = filePaths.length > 0
        ? await this.ingestor.ingest({
            rootPath: params.rootPath,
            runId: run.id,
            projectId: params.config.projectId,
            stagePlan,
            explicitFiles: [asset.filePath],
            config: params.config
          })
        : undefined;
      const agentRuntime = createAgentRuntimeFromConfig(params.config, this.agentRuntime);
      const validation = await agentRuntime.validate({
        finding,
        snapshot: snapshotForValidation ?? {
          rootPath: params.rootPath,
          runId: run.id,
          projectId: params.config.projectId,
          stage: stagePlan.name,
          files: [],
          allFileCount: 0,
          scopedFileCount: 0,
          scopeSource: "explicit_files",
          techProfile: { tags: [], manifests: [] },
          instructions: [],
          hotspots: []
        },
        assets: snapshotForValidation?.files ?? [asset],
        evidence: [...store.data.evidenceItems.filter((item) => item.findingId === finding.id), ...revalidationEvidence]
      });
      validations.push(validation);
      store.appendValidations([validation]);
      appendUsageWithBudget(store, run.id, agentRuntime.drainUsage(), stagePlan.maxCostUsd);
      if (validation.fixed?.passed === true) {
        markFindingFixed(finding, run.id);
        fixed += 1;
      } else if (stillHasSignal || validation.real.passed === true || validation.real.passed === "unknown") {
        finding.latestRunId = run.id;
        finding.updatedAt = nowIso();
        stillOpen += 1;
      } else {
        markFindingFixed(finding, run.id);
        fixed += 1;
      }
    }
    store.completeRun(run.id, {
      status: "done",
      stats: {
        checked: openFindings.length,
        fixed,
        stillOpen
      }
    });
    store.flush();
    return { runId: run.id, checked: openFindings.length, fixed, stillOpen, findings: openFindings, validations };
  }
}

function createRevalidationEvidence(params: {
  runId: string;
  projectId: string;
  finding: Finding;
  asset: AssetRecord;
  stillHasSignal: boolean;
  currentSignals: Signal[];
}): EvidenceItem[] {
  const relevantSignals = params.currentSignals.filter((signal) => {
    const expected = rawCategory(signal.raw) === params.finding.category;
    return expected || params.finding.lineNumbers.some((line) => signal.lineNumbers.includes(line));
  });
  return [
    createEvidence({
      runId: params.runId,
      projectId: params.projectId,
      findingId: params.finding.id,
      assetId: params.asset.id,
      kind: "validation",
      source: "proofstrike.revalidation",
      summary: params.stillHasSignal
        ? "Current signal present during revalidation; finding remains open unless validator proves it fixed."
        : "Current signal missing during revalidation; validator must confirm whether the root cause is fixed.",
      locator: params.asset.locator,
      raw: {
        stillHasSignal: params.stillHasSignal,
        currentSignals: relevantSignals.map((signal) => ({
          slug: signal.slug,
          category: rawCategory(signal.raw),
          lines: signal.lineNumbers
        }))
      }
    })
  ];
}

function markFindingFixed(finding: Finding, runId: string): void {
  finding.status = "fixed";
  finding.latestRunId = runId;
  finding.updatedAt = nowIso();
}

function findingStillHasSignal(params: {
  finding: Finding;
  currentSignals: Signal[];
  store: JsonEvidenceStore;
}): boolean {
  const expectedSlugs = expectedSlugsForFinding(params.store, params.finding);
  const expectedCategory = params.finding.category;
  return params.currentSignals.some((signal) => {
    if (expectedSlugs.size > 0 && expectedSlugs.has(signal.slug)) return true;
    if (expectedSlugs.size === 0 && rawCategory(signal.raw) === expectedCategory) return true;
    return false;
  });
}

function expectedSlugsForFinding(store: JsonEvidenceStore, finding: Finding): Set<string> {
  const slugs = new Set<string>();
  for (const evidence of store.data.evidenceItems.filter((item) => item.findingId === finding.id)) {
    const raw = evidence.raw;
    if (raw && typeof raw === "object" && typeof (raw as { slug?: unknown }).slug === "string") {
      slugs.add((raw as { slug: string }).slug);
    }
  }
  const detailSlug = /Proofstrike matched ([A-Za-z0-9_.:-]+) in/.exec(finding.technicalDetails)?.[1];
  if (detailSlug) slugs.add(detailSlug);
  return slugs;
}

function rawCategory(raw: unknown): string | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const category = (raw as { category?: unknown }).category;
  return typeof category === "string" ? category : undefined;
}

export function createHotspotSignals(snapshot: ArtifactSnapshot): Signal[] {
  const signals: Signal[] = [];
  for (const hotspot of snapshot.hotspots) {
    const matchers = hotspot.paths.map((pattern) => picomatch(pattern.replaceAll("\\", "/")));
    for (const asset of snapshot.files) {
      if (!matchers.some((matches) => matches(asset.filePath))) continue;
      signals.push(createSignal({
        runId: snapshot.runId,
        projectId: snapshot.projectId,
        assetId: asset.id,
        kind: "hotspot_hint",
        source: "project-hotspots",
        slug: `hotspot:${hotspot.id}`,
        confidence: "medium",
        weight: 0.4,
        lineNumbers: [],
        message: hotspot.reason || `File matches hotspot ${hotspot.id}.`,
        raw: hotspot
      }));
    }
  }
  return signals;
}

export function createScopeReviewSignals(params: {
  snapshot: ArtifactSnapshot;
  stagePlan: StagePlan;
  existingSignals: Signal[];
}): Signal[] {
  if (!shouldCreateScopeReviewSignals(params.snapshot, params.stagePlan)) return [];
  const assetsWithSignals = new Set(params.existingSignals.map((signal) => signal.assetId));
  const limit = scopeCoverageLimit(params.stagePlan);
  return params.snapshot.files
    .filter((asset) => !assetsWithSignals.has(asset.id))
    .slice(0, limit)
    .map((asset) => createSignal({
      runId: params.snapshot.runId,
      projectId: params.snapshot.projectId,
      assetId: asset.id,
      kind: "ai_pretriage",
      source: "proofstrike.scope",
      slug: "scope-review",
      confidence: "low",
      weight: 0.15,
      lineNumbers: [],
      message: "File is in the scoped review set even though no deterministic matcher fired.",
      raw: {
        slug: "scope-review",
        category: "coverage",
        severity: "info",
        scopeSource: params.snapshot.scopeSource
      }
    }));
}

function shouldCreateScopeReviewSignals(snapshot: ArtifactSnapshot, stagePlan: StagePlan): boolean {
  if (snapshot.scopeSource === "stage_full") return false;
  if (stagePlan.name === "campaign") return false;
  return snapshot.scopedFileCount > 0;
}

function scopeCoverageLimit(stagePlan: StagePlan): number {
  if (stagePlan.maxWorkPackets === "unlimited") return 200;
  return Math.max(1, Number(stagePlan.maxWorkPackets || 10) * 3);
}

class PacketLock {
  private constructor(private readonly lockPath: string, private readonly handle: number) {}

  static acquire(rootPath: string, packetId: string, staleLockMs = 15 * 60 * 1000): PacketLock {
    const lockDir = path.resolve(rootPath, ".proofstrike", "locks");
    fs.mkdirSync(lockDir, { recursive: true });
    const lockPath = path.join(lockDir, `${packetId}.lock`);
    recoverStaleLock(lockPath, staleLockMs);
    try {
      const handle = fs.openSync(lockPath, "wx");
      fs.writeFileSync(handle, JSON.stringify({ packetId, pid: process.pid, createdAt: nowIso() }));
      return new PacketLock(lockPath, handle);
    } catch (error) {
      throw new Error(`Work packet ${packetId} is already locked: ${errorMessage(error)}`);
    }
  }

  release(): void {
    try {
      fs.closeSync(this.handle);
    } catch {
      // Ignore close failures; the unlink below is the important cleanup for future runs.
    }
    try {
      fs.unlinkSync(this.lockPath);
    } catch {
      // Lock may have been cleaned up after a stale-lock recovery race.
    }
  }
}

function recoverStaleLock(lockPath: string, staleLockMs: number): void {
  if (!fs.existsSync(lockPath)) return;
  const stat = fs.statSync(lockPath);
  if (Date.now() - stat.mtimeMs < staleLockMs) return;
  fs.unlinkSync(lockPath);
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function appendUsageWithBudget(store: JsonEvidenceStore, runId: string, usage: ModelUsageRecord[], maxCostUsd: number): void {
  if (usage.length === 0) return;
  store.appendModelUsage(usage);
  if (maxCostUsd < 0) return;
  const total = store.data.modelUsage
    .filter((record) => record.runId === runId)
    .reduce((sum, record) => sum + Number(record.estimatedCostUsd || 0), 0);
  if (total > maxCostUsd) {
    throw new Error(`Model usage budget exceeded for run ${runId}: estimated $${total.toFixed(4)} > allowed $${maxCostUsd.toFixed(4)}.`);
  }
}
