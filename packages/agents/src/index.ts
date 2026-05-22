import {
  type AssetRecord,
  type AxisVerdict,
  type Confidence,
  type EvidenceItem,
  type EvidenceLevel,
  type Finding,
  type ModelUsageRecord,
  type ProofstrikeRuntimeConfig,
  type Severity,
  type Signal,
  type ValidationVerdict,
  type WorkPacket,
  createEvidence,
  createFinding,
  createValidation,
  makeId,
  unique
} from "../../core/src/index.js";
import { type ArtifactSnapshot, readFileText } from "../../ingest/src/index.js";
import { type RenderedKnowledge } from "../../knowledge/src/index.js";
import { signalMetadataForSlug } from "../../scanner/src/index.js";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

export interface InvestigationInput {
  workPacket: WorkPacket;
  snapshot: ArtifactSnapshot;
  assets: AssetRecord[];
  signals: Signal[];
  renderedKnowledge: RenderedKnowledge;
  graphSummary?: unknown;
}

export interface InvestigationOutput {
  findings: Finding[];
  evidence: EvidenceItem[];
  usage?: ModelUsageRecord[];
}

export interface ValidationInput {
  finding: Finding;
  snapshot: ArtifactSnapshot;
  assets: AssetRecord[];
  evidence: EvidenceItem[];
}

export interface ModelMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ModelGateway {
  chatJson<T>(request: {
    model: string;
    messages: ModelMessage[];
    schemaName: string;
    temperature?: number;
    maxOutputTokens?: number;
    signal?: AbortSignal;
  }): Promise<T>;
}

export interface InvestigatorAgent {
  readonly kind: string;
  investigate(input: InvestigationInput): Promise<InvestigationOutput>;
}

export interface ValidatorAgent {
  readonly kind: string;
  validate(input: ValidationInput): Promise<ValidationVerdict>;
}

export interface UsageAwareAgent {
  drainUsage(): ModelUsageRecord[];
}

export interface PromptBundle {
  schemaName: string;
  messages: ModelMessage[];
  promptChars: number;
  sections: string[];
}

export class PromptCompiler {
  compileInvestigation(input: InvestigationInput): PromptBundle {
    const primaryAsset = input.assets.find((asset) => asset.id === input.workPacket.primaryAssetId);
    const code = renderCodeContext(input.snapshot, input.assets, input.workPacket.budget.maxPromptChars);
    const sections = [
      "You are Proofstrike, a source-code security investigator. Report only issues supported by source evidence.",
      `Stage: ${input.workPacket.stage}.`,
      `Primary asset: ${primaryAsset?.locator ?? input.workPacket.primaryAssetId}.`,
      renderSignalSection(input.signals),
      renderMatcherGuidance(input.signals),
      renderSecurityTriageInstructions(input),
      renderGraphSection(input.graphSummary),
      renderKnowledgeSection(input.renderedKnowledge),
      code,
      [
        "Output strict JSON with this shape:",
        "{\"findings\":[{\"slug\":\"string\",\"title\":\"string\",\"category\":\"string\",\"severity\":\"low|medium|high|critical\",\"confidence\":\"low|medium|high\",\"summary\":\"string\",\"technicalDetails\":\"string\",\"impact\":\"string\",\"recommendation\":\"string\",\"lineNumbers\":[1],\"cwe\":[\"CWE-...\"]}]}",
        "If evidence is weak or mitigated, return {\"findings\":[]}."
      ].join("\n")
    ].filter(Boolean);
    return {
      schemaName: "proofstrike_investigation_findings",
      messages: [
        { role: "system", content: sections[0] ?? "" },
        { role: "user", content: sections.slice(1).join("\n\n") }
      ],
      promptChars: sections.join("\n\n").length,
      sections
    };
  }

  compileValidation(input: ValidationInput): PromptBundle {
    const asset = input.assets.find((item) => item.id === input.finding.primaryAssetId);
    const code = renderCodeContext(input.snapshot, asset ? [asset] : [], 16000);
    const sections = [
      "You are Proofstrike's independent validator. Validate only from the finding, code, and evidence supplied.",
      `Finding: ${input.finding.title}`,
      `Severity: ${input.finding.severity}; confidence: ${input.finding.confidence}; category: ${input.finding.category}.`,
      input.finding.technicalDetails,
      renderEvidenceSection(input.evidence),
      code,
      [
        "Return strict JSON:",
        "{\"real\":{\"passed\":true,\"confidence\":\"medium\",\"rationale\":\"...\"},\"reachable\":{\"passed\":\"unknown\",\"confidence\":\"low\",\"rationale\":\"...\"},\"impactful\":{\"passed\":true,\"confidence\":\"medium\",\"rationale\":\"...\"},\"general\":{\"passed\":true,\"confidence\":\"medium\",\"rationale\":\"...\"},\"fixed\":{\"passed\":false,\"confidence\":\"medium\",\"rationale\":\"...\"},\"reasoningSummary\":\"...\",\"counterArgument\":\"...\",\"requiredFollowup\":[\"...\"]}"
      ].join("\n")
    ].filter(Boolean);
    return {
      schemaName: "proofstrike_validation_verdict",
      messages: [
        { role: "system", content: sections[0] ?? "" },
        { role: "user", content: sections.slice(1).join("\n\n") }
      ],
      promptChars: sections.join("\n\n").length,
      sections
    };
  }
}

export class OpenAICompatibleGateway implements ModelGateway {
  constructor(private readonly options: {
    baseUrl?: string;
    apiKey?: string;
    headers?: Record<string, string>;
  } = {}) {}

  async chatJson<T>(request: {
    model: string;
    messages: ModelMessage[];
    schemaName: string;
    temperature?: number;
    maxOutputTokens?: number;
    signal?: AbortSignal;
  }): Promise<T> {
    const baseUrl = (this.options.baseUrl ?? "https://api.openai.com/v1").replace(/\/$/, "");
    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...(this.options.headers ?? {})
    };
    if (this.options.apiKey) headers.authorization = `Bearer ${this.options.apiKey}`;
    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers,
      signal: request.signal,
      body: JSON.stringify({
        model: request.model,
        messages: request.messages,
        temperature: request.temperature ?? 0,
        max_tokens: request.maxOutputTokens,
        response_format: { type: "json_object" }
      })
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`Model gateway request failed (${response.status}): ${text.slice(0, 800)}`);
    }
    const body = await response.json() as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const content = body.choices?.[0]?.message?.content;
    if (!content) throw new Error("Model gateway returned no message content.");
    return parseJsonContent<T>(content);
  }
}

export class StaticInvestigatorAgent implements InvestigatorAgent {
  readonly kind: string;

  constructor({ kind = "static-investigator" }: { kind?: string } = {}) {
    this.kind = kind;
  }

  async investigate(input: InvestigationInput): Promise<InvestigationOutput> {
    const findings: Finding[] = [];
    const evidence: EvidenceItem[] = [];
    const primaryAsset = input.assets.find((asset) => asset.id === input.workPacket.primaryAssetId);
    if (!primaryAsset) return { findings, evidence };

    const grouped = groupSignalsBySlug(input.signals);
    for (const [slug, slugSignals] of grouped.entries()) {
      const metadata = signalMetadataForSlug(slug);
      const strongest = strongestSignal(slugSignals);
      if (!strongest || !shouldReport({ slug, signals: slugSignals, primaryAsset })) continue;

      const text = primaryAsset.filePath ? readFileText(input.snapshot.rootPath, primaryAsset.filePath) : "";
      const mitigation = mitigationSummary(text, slug);
      const evidenceLevel: EvidenceLevel = mitigation.fullyMitigated ? "static_match" : "source_reasoned";
      const confidence: Confidence = mitigation.fullyMitigated ? "low" : strongest.confidence;
      if (mitigation.fullyMitigated && metadata.severity !== "critical") continue;

      const finding = createFinding({
        projectId: input.snapshot.projectId,
        runId: input.snapshot.runId,
        primaryAssetId: primaryAsset.id,
        relatedAssetIds: input.workPacket.assetIds.filter((id) => id !== primaryAsset.id),
        title: titleForSignal(slug, metadata.name),
        category: metadata.category,
        cwe: cweForSlug(slug),
        severity: metadata.severity,
        confidence,
        evidenceLevel,
        summary: `${metadata.name} in ${primaryAsset.locator}.`,
        technicalDetails: technicalDetails({
          slug,
          primaryAsset,
          signals: slugSignals,
          mitigation,
          renderedKnowledge: input.renderedKnowledge
        }),
        impact: impactForSlug(slug),
        recommendation: recommendationForSlug(slug),
        assumptions: mitigation.assumptions,
        negativeEvidence: mitigation.negativeEvidence,
        lineNumbers: unique(slugSignals.flatMap((signal) => signal.lineNumbers)),
        producedBy: {
          agentKind: this.kind,
          workPacketId: input.workPacket.id
        }
      });
      findings.push(finding);
      evidence.push(createEvidence({
        runId: input.snapshot.runId,
        projectId: input.snapshot.projectId,
        findingId: finding.id,
        candidateId: input.workPacket.candidateIds[0],
        assetId: primaryAsset.id,
        kind: "matcher",
        source: strongest.source,
        summary: strongest.message,
        locator: primaryAsset.locator,
        startLine: strongest.lineNumbers[0],
        raw: strongest.raw
      }));
      evidence.push(createEvidence({
        runId: input.snapshot.runId,
        projectId: input.snapshot.projectId,
        findingId: finding.id,
        candidateId: input.workPacket.candidateIds[0],
        assetId: primaryAsset.id,
        kind: "model_reasoning_summary",
        source: this.kind,
        summary: mitigation.fullyMitigated
          ? "Static investigator found possible mitigation and lowered confidence."
          : "Static investigator found no obvious local mitigation in the reviewed source context.",
        locator: primaryAsset.locator
      }));
    }
    return { findings, evidence };
  }
}

export class ModelBackedInvestigatorAgent implements InvestigatorAgent {
  readonly kind = "model-backed-investigator";

  constructor(
    private readonly gateway: ModelGateway,
    private readonly compiler = new PromptCompiler(),
    private readonly model: string,
    private readonly fallback = new StaticInvestigatorAgent(),
    private readonly options: {
      allowStaticFallback?: boolean;
      maxRetries?: number;
      requestTimeoutMs?: number;
      providerName?: string;
    } = {}
  ) {}

  async investigate(input: InvestigationInput): Promise<InvestigationOutput> {
    const prompt = this.compiler.compileInvestigation(input);
    const attempts = Math.max(1, (this.options.maxRetries ?? 0) + 1);
    let lastError: unknown;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const controller = new AbortController();
      const timeout = this.options.requestTimeoutMs
        ? setTimeout(() => controller.abort(), this.options.requestTimeoutMs)
        : undefined;
      try {
        const response = await this.gateway.chatJson<unknown>({
          model: this.model,
          messages: prompt.messages,
          schemaName: prompt.schemaName,
          temperature: 0,
          maxOutputTokens: 4000,
          signal: controller.signal
        });
        const parsed = modelFindingEnvelopeSchema.safeParse(response);
        if (!parsed.success) {
          throw new AgentExecutionError("Model returned invalid investigation JSON.", {
            reason: "invalid_model_json",
            detail: parsed.error.issues.slice(0, 5),
            retryable: true
          });
        }
        if (parsed.data.findings.length === 0) {
          return {
            findings: [],
            evidence: [this.modelArtifact(input, "Model completed investigation and reported no supported findings.", {
              model: this.model,
              workPacketId: input.workPacket.id
            })],
            usage: [estimateModelUsage({
              input,
              model: this.model,
              provider: this.options.providerName,
              operation: "investigation",
              promptChars: prompt.promptChars,
              responseChars: JSON.stringify(response).length,
              attempts: attempt
            })]
          };
        }
        const output = modelDraftsToFindings(input, parsed.data.findings, this.kind, this.model);
        return {
          ...output,
          usage: [estimateModelUsage({
            input,
            model: this.model,
            provider: this.options.providerName,
            operation: "investigation",
            promptChars: prompt.promptChars,
            responseChars: JSON.stringify(response).length,
            attempts: attempt
          })]
        };
      } catch (error) {
        lastError = error;
        if (attempt === attempts) break;
      } finally {
        if (timeout) clearTimeout(timeout);
      }
    }
    return this.handleFailure(input, lastError ?? new Error("Unknown model investigation failure."));
  }

  private async handleFailure(input: InvestigationInput, detail: unknown): Promise<InvestigationOutput> {
    if (this.options.allowStaticFallback === false) {
      throw normalizeAgentError(detail, "Model-backed investigation failed.");
    }
    return this.fallbackWithDiagnostic(input, failureReason(detail), detail);
  }

  private modelArtifact(input: InvestigationInput, summary: string, raw: unknown): EvidenceItem {
    const primaryAsset = input.assets.find((asset) => asset.id === input.workPacket.primaryAssetId);
    return createEvidence({
      runId: input.snapshot.runId,
      projectId: input.snapshot.projectId,
      candidateId: input.workPacket.candidateIds[0],
      assetId: primaryAsset?.id ?? input.workPacket.primaryAssetId,
      kind: "artifact",
      source: this.kind,
      summary,
      locator: primaryAsset?.locator,
      raw
    });
  }

  private async fallbackWithDiagnostic(input: InvestigationInput, reason: string, detail: unknown): Promise<InvestigationOutput> {
    try {
      const output = await this.fallback.investigate(input);
      const primaryAsset = input.assets.find((asset) => asset.id === input.workPacket.primaryAssetId);
      return {
        findings: output.findings,
        evidence: [
          ...output.evidence,
          createEvidence({
            runId: input.snapshot.runId,
            projectId: input.snapshot.projectId,
            candidateId: input.workPacket.candidateIds[0],
            assetId: primaryAsset?.id ?? input.workPacket.primaryAssetId,
            kind: "artifact",
            source: this.kind,
            summary: `Model-backed investigation fell back to deterministic static investigation: ${reason}.`,
            locator: primaryAsset?.locator,
            raw: {
              model: this.model,
              reason,
              detail: diagnosticSummary(detail),
              workPacketId: input.workPacket.id
            }
          })
        ],
        usage: output.usage
      };
    } catch (error) {
      throw normalizeAgentError(error, "Static fallback failed after model investigation failure.");
    }
  }
}

export class AgenticRepositoryInvestigatorAgent implements InvestigatorAgent {
  readonly kind = "repository-explorer-investigator";

  constructor(
    private readonly gateway: ModelGateway,
    private readonly compiler = new PromptCompiler(),
    private readonly model: string,
    private readonly options: {
      maxTurns?: number;
      maxRetries?: number;
      requestTimeoutMs?: number;
      providerName?: string;
      allowStaticFallback?: boolean;
    } = {},
    private readonly fallback = new StaticInvestigatorAgent({ kind: "repository-explorer-static-fallback" })
  ) {}

  async investigate(input: InvestigationInput): Promise<InvestigationOutput> {
    const basePrompt = this.compiler.compileInvestigation(input);
    const maxTurns = Math.max(1, input.workPacket.budget.maxToolCalls ?? this.options.maxTurns ?? 4);
    const messages: ModelMessage[] = [
      {
        role: "system",
        content: [
          basePrompt.messages[0]?.content ?? "You are Proofstrike.",
          "You may inspect repository context through structured actions before producing findings.",
          "Return exactly one JSON action per turn. Use read_files or search when more source evidence is needed. Use finish when done."
        ].join("\n")
      },
      {
        role: "user",
        content: [
          basePrompt.messages.slice(1).map((message) => message.content).join("\n\n"),
          "",
          "Action schema:",
          "{\"action\":\"read_files|search|finish\",\"files\":[\"path\"],\"query\":\"string\",\"findings\":[...]}"
        ].join("\n")
      }
    ];
    const toolEvidence: EvidenceItem[] = [];
    let responseChars = 0;
    let attempts = 0;
    try {
      for (let turn = 1; turn <= maxTurns; turn += 1) {
        const response = await this.callJson(messages, input, turn);
        attempts += 1;
        responseChars += JSON.stringify(response).length;
        const parsed = explorationActionSchema.safeParse(response);
        if (!parsed.success) {
          throw new AgentExecutionError("Model returned invalid repository-exploration JSON.", {
            reason: "invalid_exploration_json",
            detail: parsed.error.issues.slice(0, 5),
            retryable: true
          });
        }
        if (parsed.data.action === "finish") {
          const finish = modelFindingEnvelopeSchema.safeParse({ findings: parsed.data.findings ?? [] });
          if (!finish.success) {
            throw new AgentExecutionError("Model returned invalid final findings JSON.", {
              reason: "invalid_final_findings",
              detail: finish.error.issues.slice(0, 5),
              retryable: true
            });
          }
          const output = finish.data.findings.length
            ? modelDraftsToFindings(input, finish.data.findings, this.kind, this.model)
            : {
                findings: [],
                evidence: [repositoryArtifact(input, this.kind, "Repository exploration completed with no supported findings.", {
                  model: this.model,
                  turns: turn
                })]
              };
          return {
            findings: output.findings,
            evidence: [...toolEvidence, ...output.evidence],
            usage: [estimateModelUsage({
              input,
              model: this.model,
              provider: this.options.providerName,
              operation: "investigation",
              promptChars: messages.reduce((sum, message) => sum + message.content.length, 0),
              responseChars,
              attempts
            })]
          };
        }
        const observation = this.runToolAction(input, parsed.data);
        toolEvidence.push(observation.evidence);
        messages.push({ role: "assistant", content: JSON.stringify(response) });
        messages.push({ role: "user", content: observation.message });
      }
      throw new AgentExecutionError("Repository exploration exhausted its turn budget before a final verdict.", {
        reason: "exploration_turn_budget_exhausted",
        retryable: false
      });
    } catch (error) {
      if (this.options.allowStaticFallback === false) throw normalizeAgentError(error, "Repository exploration failed.");
      const output = await this.fallback.investigate(input);
      return {
        findings: output.findings,
        evidence: [
          ...toolEvidence,
          ...output.evidence,
          repositoryArtifact(input, this.kind, `Repository exploration fell back to deterministic static investigation: ${failureReason(error)}.`, {
            model: this.model,
            detail: diagnosticSummary(error)
          })
        ],
        usage: output.usage
      };
    }
  }

  private async callJson(messages: ModelMessage[], input: InvestigationInput, turn: number): Promise<unknown> {
    const attempts = Math.max(1, (this.options.maxRetries ?? 0) + 1);
    let lastError: unknown;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const controller = new AbortController();
      const timeout = this.options.requestTimeoutMs
        ? setTimeout(() => controller.abort(), this.options.requestTimeoutMs)
        : undefined;
      try {
        return await this.gateway.chatJson<unknown>({
          model: this.model,
          messages,
          schemaName: "proofstrike_repository_explorer_action",
          temperature: 0,
          maxOutputTokens: 4000,
          signal: controller.signal
        });
      } catch (error) {
        lastError = error;
        if (attempt === attempts) break;
      } finally {
        if (timeout) clearTimeout(timeout);
      }
    }
    throw normalizeAgentError(lastError, `Repository exploration model call failed at turn ${turn}.`);
  }

  private runToolAction(input: InvestigationInput, action: ExplorationAction): { message: string; evidence: EvidenceItem } {
    if (action.action === "search") return searchRepository(input, this.kind, action.query ?? "");
    return readRepositoryFiles(input, this.kind, action.files ?? []);
  }
}

export class IndependentValidatorAgent implements ValidatorAgent {
  readonly kind: string;

  constructor({ kind = "fact-decomposing-validator" }: { kind?: string } = {}) {
    this.kind = kind;
  }

  async validate(input: ValidationInput): Promise<ValidationVerdict> {
    const asset = input.assets.find((item) => item.id === input.finding.primaryAssetId);
    const text = asset?.filePath ? readFileText(input.snapshot.rootPath, asset.filePath) : "";
    const mitigation = mitigationSummary(text, slugFromCategory(input.finding.category));
    const facts = decomposeFindingFacts(input.finding, input.evidence, text);
    const verifiedFacts = facts.filter((fact) => fact.verified).length;
    const factRatio = facts.length ? verifiedFacts / facts.length : 0;
    const revalidationMode = input.evidence.some((item) => item.source === "proofstrike.revalidation");
    const currentSignalPresent = input.evidence.some((item) => item.source === "proofstrike.revalidation" && /current signal present/i.test(item.summary));
    const currentSignalMissing = input.evidence.some((item) => item.source === "proofstrike.revalidation" && /current signal missing/i.test(item.summary));
    const sinkPresent = sinkStillLooksPresent(input.finding, text);
    const fixedPassed = revalidationMode && currentSignalMissing && !sinkPresent;
    const realPassed = !fixedPassed && !mitigation.fullyMitigated && (
      input.finding.evidenceLevel === "source_reasoned" ||
      input.finding.evidenceLevel === "reachable_reasoned" ||
      factRatio >= 0.6 ||
      currentSignalPresent
    );
    const reachable = isProbablyReachable(text, asset);
    const impactful = ["critical", "high"].includes(input.finding.severity) || input.finding.category === "secrets";
    const general = input.evidence.length > 0;
    return createValidation({
      findingId: input.finding.id,
      runId: input.snapshot.runId,
      validatorKind: this.kind,
      adjustedSeverity: input.finding.severity,
      adjustedEvidenceLevel: realPassed ? input.finding.evidenceLevel : "static_match",
      axes: {
        real: axis(realPassed, realPassed ? `Verified ${verifiedFacts}/${facts.length || 1} decomposed fact(s) and found no complete local mitigation.` : "Fact checks did not sufficiently support the finding or found likely mitigation."),
        reachable: axis(reachable ? true : "unknown", reachable ? "File looks route/API reachable or contains handler code." : "Reachability was not proven from local static context."),
        impactful: axis(impactful, impactful ? "Severity/category implies meaningful security impact if reachable." : "Impact is limited or needs manual review."),
        general: axis(general && factRatio >= 0.4, general ? `Finding has recorded evidence; fact support ratio is ${factRatio.toFixed(2)}.` : "No evidence items were attached.")
      },
      fixed: axis(fixedPassed, fixedPassed ? "Revalidation found the original signal missing and the decomposed facts no longer supported by source." : "Revalidation did not prove that the issue is fixed."),
      reasoningSummary: realPassed
        ? "Validator decomposed the finding into checkable facts and found enough source support to keep it open."
        : "Validator lowered confidence because fact support was weak, missing, or mitigated.",
      counterArgument: mitigation.negativeEvidence.join(" ") || "A framework-level or cross-file mitigation may still exist outside this context.",
      requiredFollowup: reachable || fixedPassed ? [] : ["Confirm route reachability and framework-level auth middleware."]
    });
  }
}

export class ModelBackedValidatorAgent implements ValidatorAgent, UsageAwareAgent {
  readonly kind = "model-backed-consensus-validator";
  private readonly usage: ModelUsageRecord[] = [];

  constructor(
    private readonly gateway: ModelGateway,
    private readonly compiler = new PromptCompiler(),
    private readonly model: string,
    private readonly fallback = new IndependentValidatorAgent(),
    private readonly options: {
      runs?: number;
      allowStaticFallback?: boolean;
      requestTimeoutMs?: number;
      providerName?: string;
    } = {}
  ) {}

  async validate(input: ValidationInput): Promise<ValidationVerdict> {
    const runs = Math.max(1, this.options.runs ?? 1);
    const prompt = this.compiler.compileValidation(input);
    const verdicts: ValidationVerdict[] = [];
    let responseChars = 0;
    try {
      for (let index = 0; index < runs; index += 1) {
        const controller = new AbortController();
        const timeout = this.options.requestTimeoutMs
          ? setTimeout(() => controller.abort(), this.options.requestTimeoutMs)
          : undefined;
        try {
          const response = await this.gateway.chatJson<unknown>({
            model: this.model,
            messages: prompt.messages,
            schemaName: prompt.schemaName,
            temperature: 0,
            maxOutputTokens: 2000,
            signal: controller.signal
          });
          responseChars += JSON.stringify(response).length;
          const parsed = validationEnvelopeSchema.safeParse(response);
          if (!parsed.success) {
            throw new AgentExecutionError("Model returned invalid validation JSON.", {
              reason: "invalid_validation_json",
              detail: parsed.error.issues.slice(0, 5),
              retryable: true
            });
          }
          verdicts.push(createValidation({
            findingId: input.finding.id,
            runId: input.snapshot.runId,
            validatorKind: this.kind,
            model: this.model,
            adjustedSeverity: input.finding.severity,
            adjustedEvidenceLevel: parsed.data.real.passed === true ? input.finding.evidenceLevel : "static_match",
            axes: {
              real: parsed.data.real,
              reachable: parsed.data.reachable,
              impactful: parsed.data.impactful,
              general: parsed.data.general
            },
            fixed: parsed.data.fixed,
            reasoningSummary: parsed.data.reasoningSummary,
            counterArgument: parsed.data.counterArgument,
            requiredFollowup: parsed.data.requiredFollowup
          }));
        } finally {
          if (timeout) clearTimeout(timeout);
        }
      }
      this.usage.push(estimateModelUsage({
        input: {
          snapshot: input.snapshot,
          workPacket: {
            id: input.finding.producedBy.workPacketId,
            runId: input.snapshot.runId,
            projectId: input.snapshot.projectId,
            stage: "campaign",
            agentKind: this.kind,
            primaryAssetId: input.finding.primaryAssetId,
            assetIds: input.finding.relatedAssetIds,
            candidateIds: [],
            signalIds: [],
            codeContext: [],
            graphContext: [],
            knowledgePackIds: [],
            projectInstructionIds: [],
            historyRefs: [],
            budget: { maxCostUsd: 0, maxPromptChars: prompt.promptChars },
            outputSchema: "validation_verdict",
            status: "done"
          },
          assets: input.assets,
          signals: [],
          renderedKnowledge: { packIds: [], text: "" }
        },
        model: this.model,
        provider: this.options.providerName,
        operation: "validation",
        promptChars: prompt.promptChars * runs,
        responseChars,
        attempts: runs
      }));
      return consensusValidation(input, verdicts);
    } catch (error) {
      if (this.options.allowStaticFallback === false) throw normalizeAgentError(error, "Model-backed validation failed.");
      return this.fallback.validate(input);
    }
  }

  drainUsage(): ModelUsageRecord[] {
    const drained = [...this.usage];
    this.usage.length = 0;
    return drained;
  }
}

export class AgentRuntime {
  private readonly usage: ModelUsageRecord[] = [];

  constructor(
    private readonly investigator: InvestigatorAgent = new StaticInvestigatorAgent(),
    private readonly validator: ValidatorAgent = new IndependentValidatorAgent()
  ) {}

  async investigate(params: InvestigationInput): Promise<InvestigationOutput> {
    const output = await this.investigator.investigate(params);
    this.usage.push(...(output.usage ?? []), ...drainUsage(this.investigator));
    return output;
  }

  async validate(params: ValidationInput): Promise<ValidationVerdict> {
    const verdict = await this.validator.validate(params);
    this.usage.push(...drainUsage(this.validator));
    return verdict;
  }

  drainUsage(): ModelUsageRecord[] {
    const drained = [...this.usage];
    this.usage.length = 0;
    return drained;
  }
}

export function createAgentRuntimeFromConfig(
  config: { providers?: Record<string, unknown>; runtime?: ProofstrikeRuntimeConfig },
  fallback = new AgentRuntime()
): AgentRuntime {
  const provider = resolveDefaultProvider(config.providers);
  if (!provider) return fallback;
  const apiKey = provider.apiKey ?? (provider.apiKeyEnv ? process.env[provider.apiKeyEnv] : undefined);
  if (!apiKey && provider.requireApiKey !== false) {
    if (config.runtime?.modelFailureMode === "static-fallback") return fallback;
    throw new AgentExecutionError(`Configured model provider requires an API key (${provider.apiKeyEnv ?? "apiKey"}).`, {
      reason: "missing_provider_api_key",
      retryable: false
    });
  }
  const gateway = new OpenAICompatibleGateway({
    baseUrl: provider.baseUrl,
    apiKey,
    headers: provider.headers
  });
  const promptCompiler = new PromptCompiler();
  const allowStaticFallback = config.runtime?.modelFailureMode === "static-fallback";
  const sharedOptions = {
    allowStaticFallback,
    maxRetries: config.runtime?.retries,
    requestTimeoutMs: config.runtime?.requestTimeoutMs,
    providerName: provider.name
  };
  const investigator = config.runtime?.agentMode === "single-pass"
    ? new ModelBackedInvestigatorAgent(gateway, promptCompiler, provider.model, new StaticInvestigatorAgent(), sharedOptions)
    : new AgenticRepositoryInvestigatorAgent(gateway, promptCompiler, provider.model, {
        ...sharedOptions,
        maxTurns: config.runtime?.explorationTurns
      });
  const validator = new ModelBackedValidatorAgent(gateway, promptCompiler, provider.model, new IndependentValidatorAgent(), {
    runs: config.runtime?.validationRuns,
    allowStaticFallback,
    requestTimeoutMs: config.runtime?.requestTimeoutMs,
    providerName: provider.name
  });
  return new AgentRuntime(investigator, validator);
}

const modelFindingEnvelopeSchema = z.object({
  findings: z.array(z.object({
    slug: z.string().optional(),
    title: z.string().min(1),
    category: z.string().min(1),
    severity: z.enum(["low", "medium", "high", "critical"]),
    confidence: z.enum(["low", "medium", "high"]).default("medium"),
    summary: z.string().min(1),
    technicalDetails: z.string().min(1),
    impact: z.string().min(1),
    recommendation: z.string().min(1),
    lineNumbers: z.array(z.number().int().positive()).default([]),
    cwe: z.array(z.string()).default([]),
    assumptions: z.array(z.string()).default([]),
    negativeEvidence: z.array(z.string()).default([])
  })).default([])
});

type ModelFindingDraft = z.infer<typeof modelFindingEnvelopeSchema>["findings"][number];

const axisVerdictSchema = z.object({
  passed: z.union([z.boolean(), z.literal("unknown")]),
  confidence: z.enum(["low", "medium", "high"]),
  rationale: z.string().min(1)
});

const validationEnvelopeSchema = z.object({
  real: axisVerdictSchema,
  reachable: axisVerdictSchema,
  impactful: axisVerdictSchema,
  general: axisVerdictSchema,
  fixed: axisVerdictSchema.optional(),
  reasoningSummary: z.string().min(1),
  counterArgument: z.string().default(""),
  requiredFollowup: z.array(z.string()).default([])
});

const explorationActionSchema = z.object({
  action: z.enum(["read_files", "search", "finish"]),
  files: z.array(z.string()).default([]),
  query: z.string().optional(),
  findings: modelFindingEnvelopeSchema.shape.findings.optional()
});

type ExplorationAction = z.infer<typeof explorationActionSchema>;

export class AgentExecutionError extends Error {
  readonly reason: string;
  readonly retryable: boolean;
  readonly detail?: unknown;

  constructor(message: string, options: { reason: string; retryable?: boolean; detail?: unknown }) {
    super(message);
    this.name = "AgentExecutionError";
    this.reason = options.reason;
    this.retryable = options.retryable ?? false;
    this.detail = options.detail;
  }
}

function shouldReport(params: { slug: string; signals: Signal[]; primaryAsset: AssetRecord }): boolean {
  if (params.slug === "scope-review" || params.slug.startsWith("hotspot:")) return false;
  if (params.slug === "missing-auth" && params.primaryAsset.filePath?.includes(".test.")) return false;
  return params.signals.length > 0;
}

function mitigationSummary(text: string, slug: string): {
  fullyMitigated: boolean;
  negativeEvidence: string[];
  assumptions: string[];
} {
  const negativeEvidence: string[] = [];
  const assumptions: string[] = [];
  if (/\b(requireAuth|requireUser|requireAdmin|authorize|permission|role|getServerSession|verifyToken)\b/i.test(text)) {
    negativeEvidence.push("The file contains an auth-related symbol; verify whether it protects the vulnerable path.");
  }
  if (/\b(parameterized|prepare|bind|where\(|eq\(|sql`)/i.test(text)) {
    negativeEvidence.push("The file contains query-construction terms that may indicate parameterization.");
  }
  if (/\b(escape|sanitize|allowlist|whitelist|zod|joi|yup|schema|validate)\b/i.test(text)) {
    negativeEvidence.push("The file contains validation or sanitization-related terms.");
  }
  if (slug === "secrets-exposure") {
    assumptions.push("Assumes the matched value is not a documented test-only fake secret.");
  } else {
    assumptions.push("Static review did not execute the application.");
  }
  return {
    fullyMitigated: negativeEvidence.length >= 2 && slug !== "secrets-exposure",
    negativeEvidence,
    assumptions
  };
}

function technicalDetails(params: {
  slug: string;
  primaryAsset: AssetRecord;
  signals: Signal[];
  mitigation: ReturnType<typeof mitigationSummary>;
  renderedKnowledge: RenderedKnowledge;
}): string {
  const lines = unique(params.signals.flatMap((signal) => signal.lineNumbers));
  const lineText = lines.length ? ` Lines: ${lines.join(", ")}.` : "";
  const knowledgeText = params.renderedKnowledge.packIds.length ? ` Knowledge packs: ${params.renderedKnowledge.packIds.join(", ")}.` : "";
  const mitigationText = params.mitigation.negativeEvidence.length
    ? ` Mitigation signals checked: ${params.mitigation.negativeEvidence.join(" ")}`
    : " No obvious local mitigation was detected.";
  return `Proofstrike matched ${params.slug} in ${params.primaryAsset.locator}.${lineText}${knowledgeText}${mitigationText}`;
}

function titleForSignal(slug: string, name: string): string {
  if (slug === "secrets-exposure") return "Potential secret committed to source";
  return name;
}

function impactForSlug(slug: string): string {
  const impacts: Record<string, string> = {
    "secrets-exposure": "Attackers may use exposed credentials to access internal or third-party systems.",
    "env-exposure": "Secret-bearing values may be exposed to a client bundle or public runtime.",
    "secret-in-log": "Sensitive tokens or credentials may be persisted in logs accessible to operators or attackers.",
    "sql-injection": "Attackers may read or modify data if untrusted input reaches this query.",
    "prisma-raw-sql": "Attackers may read or modify data if untrusted input reaches raw SQL.",
    "drizzle-raw-sql": "Attackers may read or modify data if untrusted input reaches raw SQL.",
    "nosql-injection": "Attackers may alter NoSQL query shape if untrusted object data reaches this query.",
    "mass-assignment": "Attackers may set fields that should be server-controlled, including roles, owners, or tenant IDs.",
    "tenant-id-from-request": "Attackers may cross tenant or workspace boundaries if request-supplied scope IDs are trusted.",
    "command-injection": "Attackers may execute system commands if input reaches this sink.",
    "unsafe-deserialization": "Attackers may execute code or alter object state if untrusted serialized data is accepted.",
    "prototype-pollution": "Attackers may poison object prototypes or overwrite privileged fields.",
    ssrf: "Attackers may cause server-side requests to internal or trusted services.",
    "untrusted-redirect-following": "Attackers may pivot SSRF through redirects if allowlists only check the first URL.",
    "file-upload-unrestricted": "Attackers may upload unexpected files, oversized content, or executable payloads.",
    "cors-wildcard": "Browsers may allow cross-origin reads where the API expected same-origin access.",
    "cors-credentials-wildcard": "Credentialed cross-origin access can expose authenticated data to untrusted origins.",
    "session-cookie-insecure": "Session cookies may be exposed to script access or plaintext transport.",
    "jwt-decode-without-verify": "Attackers may forge identity or authorization claims if decoded JWTs are trusted.",
    "jwt-algorithm-confusion": "Attackers may bypass signature checks if unsafe JWT algorithms are accepted.",
    "public-admin-route": "Unauthenticated users may reach administrative behavior.",
    "missing-auth": "Unauthenticated or under-authorized users may access sensitive behavior.",
    "debug-endpoint": "Debug endpoints may leak internals or allow privileged operations.",
    "error-message-leak": "Raw errors may disclose stack traces, secrets, queries, or internal paths.",
    "ai-tool-boundary": "Untrusted model output or user input may reach privileged tool execution.",
    "mcp-tool-handler": "Untrusted MCP/tool calls may reach privileged behavior without application-layer checks.",
    "prompt-injection-untrusted-content": "Untrusted content may override or contaminate model instructions.",
    "system-prompt-leak": "System or developer prompts may be disclosed to users.",
    "agent-loop-no-cap": "Unbounded agent loops can create spend, availability, or repeated side-effect risk.",
    "github-pull-request-target": "Untrusted pull request data may execute with privileged repository tokens.",
    "github-script-injection": "Pull request context may be interpolated into a privileged GitHub Script step.",
    "github-action-unpinned": "A compromised mutable action tag can alter CI behavior.",
    "package-install-script": "Install scripts can execute code during dependency installation.",
    "dockerfile-curl-pipe": "Remote script execution during image build can compromise the supply chain.",
    "terraform-public-ingress": "Sensitive services may be reachable from the public internet.",
    "terraform-iam-wildcard": "Wildcard IAM permissions increase blast radius after credential compromise.",
    "kubernetes-privileged-container": "Privileged containers can escape isolation or access host resources."
  };
  return impacts[slug] || "The issue may cross a security boundary if reachable.";
}

function recommendationForSlug(slug: string): string {
  const recommendations: Record<string, string> = {
    "secrets-exposure": "Remove the secret, rotate it, and load it from a secret manager or environment variable.",
    "env-exposure": "Rename the variable and ensure secret values are loaded only on the server side.",
    "secret-in-log": "Remove sensitive values from logs and add structured redaction for credentials and tokens.",
    "sql-injection": "Use parameterized queries or a safe query builder and add tests for malicious input.",
    "prisma-raw-sql": "Use parameterized Prisma raw queries or query-builder APIs instead of unsafe raw SQL.",
    "drizzle-raw-sql": "Use parameter placeholders or query-builder APIs and avoid interpolating request data.",
    "nosql-injection": "Validate request bodies and construct database filters from typed allowlisted fields.",
    "mass-assignment": "Build persistence inputs from an allowlist or schema-based DTO instead of raw request bodies.",
    "tenant-id-from-request": "Derive tenant scope from authenticated membership and enforce tenant predicates in data access.",
    "command-injection": "Avoid shell execution; if required, pass arguments as arrays and allowlist accepted values.",
    "unsafe-deserialization": "Avoid unsafe deserialization for untrusted data; use typed safe formats and schema validation.",
    "prototype-pollution": "Reject dangerous keys such as __proto__/constructor/prototype and avoid deep merging untrusted objects.",
    ssrf: "Use URL allowlists, block internal address ranges, and avoid following untrusted redirects.",
    "file-upload-unrestricted": "Add file size limits, MIME/content validation, storage isolation, and malware scanning where appropriate.",
    "cors-wildcard": "Restrict CORS origins to known trusted origins and avoid reflecting arbitrary origins.",
    "cors-credentials-wildcard": "Disable credentialed wildcard CORS and explicitly allow only trusted origins.",
    "session-cookie-insecure": "Set httpOnly, secure, sameSite, path, and expiry attributes appropriate for the session model.",
    "jwt-decode-without-verify": "Verify JWT signature, issuer, audience, expiry, and accepted algorithms before trusting claims.",
    "jwt-algorithm-confusion": "Pin accepted JWT algorithms and reject none/algorithm confusion paths.",
    "public-admin-route": "Add backend authentication and authorization checks for the admin route.",
    "missing-auth": "Add explicit authentication and authorization checks at the backend handler boundary.",
    "debug-endpoint": "Remove the endpoint or protect it with internal-network and admin authorization checks.",
    "error-message-leak": "Return generic errors to clients and log detailed diagnostics only in protected logs.",
    "ai-tool-boundary": "Enforce authorization inside the tool implementation and require typed, validated arguments.",
    "mcp-tool-handler": "Validate MCP tool arguments and enforce authorization inside each handler.",
    "prompt-injection-untrusted-content": "Keep untrusted content in data fields, not instruction fields, and add prompt-injection guardrails.",
    "system-prompt-leak": "Keep system/developer prompts server-side and avoid returning them through API responses.",
    "agent-loop-no-cap": "Add max turns, timeouts, budget limits, cancellation, and audit logs around agent loops.",
    "github-pull-request-target": "Avoid pull_request_target for untrusted code or separate privileged steps from PR-controlled input.",
    "github-script-injection": "Avoid interpolating PR-controlled values into scripts; pass data via environment variables and quote safely.",
    "github-action-unpinned": "Pin third-party actions to immutable commit SHAs.",
    "package-install-script": "Remove lifecycle scripts where possible or document and isolate trusted install-time behavior.",
    "dockerfile-curl-pipe": "Download pinned artifacts with checksum/signature verification before executing.",
    "terraform-public-ingress": "Restrict ingress CIDRs to trusted networks and avoid exposing administrative ports.",
    "terraform-iam-wildcard": "Replace wildcard IAM actions/resources with least-privilege statements.",
    "kubernetes-privileged-container": "Disable privileged/host settings and use a restricted security context."
  };
  return recommendations[slug] || "Add validation, authorization, and regression tests around the risky path.";
}

function cweForSlug(slug: string): string[] {
  const cwes: Record<string, string[]> = {
    "sql-injection": ["CWE-89"],
    "prisma-raw-sql": ["CWE-89"],
    "drizzle-raw-sql": ["CWE-89"],
    "nosql-injection": ["CWE-943"],
    "mass-assignment": ["CWE-915"],
    "tenant-id-from-request": ["CWE-639"],
    "command-injection": ["CWE-78"],
    "unsafe-deserialization": ["CWE-502"],
    "prototype-pollution": ["CWE-1321"],
    ssrf: ["CWE-918"],
    "path-traversal": ["CWE-22"],
    "dangerous-html": ["CWE-79"],
    "postmessage-origin": ["CWE-346"],
    "regex-dos": ["CWE-1333"],
    "open-redirect": ["CWE-601"],
    "cors-wildcard": ["CWE-942"],
    "cors-credentials-wildcard": ["CWE-942"],
    "session-cookie-insecure": ["CWE-614", "CWE-1004"],
    "jwt-decode-without-verify": ["CWE-347"],
    "jwt-algorithm-confusion": ["CWE-347"],
    "public-admin-route": ["CWE-306"],
    "missing-auth": ["CWE-306"],
    "secrets-exposure": ["CWE-798"],
    "env-exposure": ["CWE-798"],
    "secret-in-log": ["CWE-532"],
    "webhook-no-signature": ["CWE-345"],
    "ai-tool-boundary": ["CWE-862"],
    "mcp-tool-handler": ["CWE-862"],
    "prompt-injection-untrusted-content": ["CWE-94"],
    "system-prompt-leak": ["CWE-200"],
    "github-pull-request-target": ["CWE-829"],
    "github-script-injection": ["CWE-94"],
    "github-action-unpinned": ["CWE-829"],
    "dockerfile-curl-pipe": ["CWE-494"],
    "terraform-public-ingress": ["CWE-284"],
    "terraform-iam-wildcard": ["CWE-266"],
    "kubernetes-privileged-container": ["CWE-250"]
  };
  return cwes[slug] || [];
}

function slugFromCategory(category: string): string {
  const map: Record<string, string> = {
    secrets: "secrets-exposure",
    injection: "sql-injection",
    rce: "command-injection",
    auth: "missing-auth",
    ssrf: "ssrf",
    "ai-appsec": "ai-tool-boundary"
  };
  return map[category] || category;
}

interface FindingFact {
  label: string;
  verified: boolean;
  rationale: string;
}

function decomposeFindingFacts(finding: Finding, evidence: EvidenceItem[], sourceText: string): FindingFact[] {
  const lower = sourceText.toLowerCase();
  const evidenceText = evidence.map((item) => `${item.summary} ${JSON.stringify(item.raw ?? {})}`).join("\n").toLowerCase();
  const terms = unique([
    finding.category,
    ...finding.title.toLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length > 4).slice(0, 4),
    ...finding.cwe
  ]);
  const lineEvidence = finding.lineNumbers.length === 0 || finding.lineNumbers.some((line) => sourceLineExists(sourceText, line));
  return [
    {
      label: "Finding has recorded evidence",
      verified: evidence.length > 0,
      rationale: evidence.length ? `${evidence.length} evidence item(s) are attached.` : "No evidence items are attached."
    },
    {
      label: "Primary source lines still exist",
      verified: lineEvidence,
      rationale: lineEvidence ? "Referenced line evidence is still present or line-specific evidence was not required." : "Referenced source lines are no longer present."
    },
    {
      label: "Security category terms are still supported",
      verified: terms.some((term) => lower.includes(term.toLowerCase()) || evidenceText.includes(term.toLowerCase())),
      rationale: `Checked terms: ${terms.join(", ") || finding.category}.`
    },
    {
      label: "Sink or boundary still appears in source",
      verified: sinkStillLooksPresent(finding, sourceText),
      rationale: "Checked category-specific sink and boundary patterns in the current source."
    }
  ];
}

function sourceLineExists(text: string, lineNumber: number): boolean {
  const lines = text.split(/\r?\n/);
  const line = lines[lineNumber - 1];
  return typeof line === "string" && line.trim().length > 0;
}

function sinkStillLooksPresent(finding: Finding, text: string): boolean {
  if (!text.trim()) return false;
  const category = finding.category.toLowerCase();
  if (category === "injection") {
    return /\b(?:db|client|conn|connection|cursor|tx|prisma|sequelize|knex|pool)\.(?:query|execute|raw|exec|executeRaw|queryRaw|queryRawUnsafe)\s*\([^)]*(?:req\.|request\.|params|query|body|\+|\$\{|format\(|f["'])|["'`](?:select|update|delete|insert)[^"'`]*(?:\+|\$\{)/i.test(text);
  }
  if (category === "rce") return /\b(?:exec|spawn|system|eval|Function|subprocess|Runtime\.getRuntime)\b/i.test(text);
  if (category === "auth") return /\b(?:route|router|controller|handler|admin|authorize|jwt|session|permission|role|publicProcedure|AllowAnonymous)\b/i.test(text);
  if (category === "secrets") return /\b(?:secret|token|password|api[_-]?key|private[_-]?key)\b\s*[:=]\s*["'][^"']{8,}["']/i.test(text);
  if (category === "ssrf") return /\b(?:fetch|axios|requests\.get|http\.Get|client\.Get|open-uri)\s*\([^)]*(?:req\.|request\.|params|query|body|url)\b/i.test(text);
  if (category === "path-traversal") return /\b(?:readFile|createReadStream|sendFile|download|open)\s*\([^)]*(?:req\.|request\.|params|query|body|filename|path)\b/i.test(text);
  if (category === "ai-appsec") return /\b(?:tool|prompt|system|developer|messages|agent|mcp|function_call)\b/i.test(text);
  return finding.lineNumbers.some((line) => sourceLineExists(text, line));
}

function consensusValidation(input: ValidationInput, verdicts: ValidationVerdict[]): ValidationVerdict {
  if (verdicts.length === 1) return verdicts[0]!;
  const realVotes = verdicts.map((item) => item.real.passed);
  const reachableVotes = verdicts.map((item) => item.reachable.passed);
  const impactfulVotes = verdicts.map((item) => item.impactful.passed);
  const generalVotes = verdicts.map((item) => item.general.passed);
  const fixedVotes = verdicts.map((item) => item.fixed?.passed ?? false);
  const confidence = consistencyConfidence(realVotes);
  return createValidation({
    findingId: input.finding.id,
    runId: input.snapshot.runId,
    validatorKind: "model-backed-consensus-validator",
    model: verdicts[0]?.model,
    adjustedSeverity: input.finding.severity,
    adjustedEvidenceLevel: majority(realVotes) === true ? input.finding.evidenceLevel : "static_match",
    axes: {
      real: axisWithConfidence(majority(realVotes), confidence, `Consensus across ${verdicts.length} validation run(s): ${voteSummary(realVotes)}.`),
      reachable: axisWithConfidence(majority(reachableVotes), consistencyConfidence(reachableVotes), `Consensus: ${voteSummary(reachableVotes)}.`),
      impactful: axisWithConfidence(majority(impactfulVotes), consistencyConfidence(impactfulVotes), `Consensus: ${voteSummary(impactfulVotes)}.`),
      general: axisWithConfidence(majority(generalVotes), consistencyConfidence(generalVotes), `Consensus: ${voteSummary(generalVotes)}.`)
    },
    fixed: axisWithConfidence(majority(fixedVotes), consistencyConfidence(fixedVotes), `Consensus: ${voteSummary(fixedVotes)}.`),
    reasoningSummary: verdicts.map((item, index) => `Run ${index + 1}: ${item.reasoningSummary}`).join(" "),
    counterArgument: unique(verdicts.map((item) => item.counterArgument).filter(Boolean)).join(" "),
    requiredFollowup: unique(verdicts.flatMap((item) => item.requiredFollowup))
  });
}

function majority(values: Array<boolean | "unknown">): boolean | "unknown" {
  const trueCount = values.filter((value) => value === true).length;
  const falseCount = values.filter((value) => value === false).length;
  if (trueCount > falseCount && trueCount >= Math.ceil(values.length / 2)) return true;
  if (falseCount > trueCount && falseCount >= Math.ceil(values.length / 2)) return false;
  return "unknown";
}

function consistencyConfidence(values: Array<boolean | "unknown">): Confidence {
  const counts = new Map<boolean | "unknown", number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  const strongest = Math.max(...counts.values());
  if (strongest === values.length) return "high";
  if (strongest >= Math.ceil(values.length / 2)) return "medium";
  return "low";
}

function voteSummary(values: Array<boolean | "unknown">): string {
  return `true=${values.filter((value) => value === true).length}, false=${values.filter((value) => value === false).length}, unknown=${values.filter((value) => value === "unknown").length}`;
}

function axisWithConfidence(passed: boolean | "unknown", confidence: Confidence, rationale: string): AxisVerdict {
  return { passed, confidence, rationale };
}

function isProbablyReachable(text: string, asset?: AssetRecord): boolean {
  return Boolean(
    asset?.type === "route" ||
      asset?.filePath?.includes("/api/") ||
      /(?:app|router)\.(?:get|post|put|patch|delete)|export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)/.test(text)
  );
}

function axis(passed: AxisVerdict["passed"], rationale: string): AxisVerdict {
  return {
    passed,
    confidence: passed === true ? "medium" : "low",
    rationale
  };
}

function groupSignalsBySlug(signals: Signal[]): Map<string, Signal[]> {
  const grouped = new Map<string, Signal[]>();
  for (const signal of signals) {
    const current = grouped.get(signal.slug) ?? [];
    current.push(signal);
    grouped.set(signal.slug, current);
  }
  return grouped;
}

function strongestSignal(signals: Signal[]): Signal | undefined {
  return [...signals].sort((a, b) => Number(b.weight || 0) - Number(a.weight || 0))[0];
}

function modelDraftsToFindings(
  input: InvestigationInput,
  drafts: ModelFindingDraft[],
  agentKind: string,
  model: string
): InvestigationOutput {
  const findings: Finding[] = [];
  const evidence: EvidenceItem[] = [];
  const primaryAsset = input.assets.find((asset) => asset.id === input.workPacket.primaryAssetId);
  if (!primaryAsset) return { findings, evidence };
  const strongest = strongestSignal(input.signals);
  for (const draft of drafts) {
    const slug = draft.slug || strongest?.slug || draft.category;
    const finding = createFinding({
      projectId: input.snapshot.projectId,
      runId: input.snapshot.runId,
      primaryAssetId: primaryAsset.id,
      relatedAssetIds: input.workPacket.assetIds.filter((id) => id !== primaryAsset.id),
      title: draft.title,
      category: draft.category,
      cwe: draft.cwe,
      severity: draft.severity,
      confidence: draft.confidence,
      evidenceLevel: "source_reasoned",
      summary: draft.summary,
      technicalDetails: draft.technicalDetails,
      impact: draft.impact,
      recommendation: draft.recommendation,
      assumptions: draft.assumptions,
      negativeEvidence: draft.negativeEvidence,
      lineNumbers: unique(draft.lineNumbers),
      producedBy: {
        agentKind,
        model,
        workPacketId: input.workPacket.id
      }
    });
    findings.push(finding);
    if (strongest) {
      evidence.push(createEvidence({
        runId: input.snapshot.runId,
        projectId: input.snapshot.projectId,
        findingId: finding.id,
        candidateId: input.workPacket.candidateIds[0],
        assetId: primaryAsset.id,
        kind: "matcher",
        source: strongest.source,
        summary: strongest.message,
        locator: primaryAsset.locator,
        startLine: strongest.lineNumbers[0],
        raw: { ...(typeof strongest.raw === "object" && strongest.raw ? strongest.raw : {}), slug }
      }));
    }
    evidence.push(createEvidence({
      runId: input.snapshot.runId,
      projectId: input.snapshot.projectId,
      findingId: finding.id,
      candidateId: input.workPacket.candidateIds[0],
      assetId: primaryAsset.id,
      kind: "model_reasoning_summary",
      source: agentKind,
      summary: `Model ${model} produced a source-reasoned finding from the supplied work packet.`,
      locator: primaryAsset.locator,
      raw: { model, slug }
    }));
  }
  return { findings, evidence };
}

function renderSignalSection(signals: Signal[]): string {
  if (signals.length === 0) return "Signals: none.";
  const lines = signals.slice(0, 25).map((signal) =>
    `- ${signal.slug} (${signal.confidence}, weight ${signal.weight}) lines ${signal.lineNumbers.join(", ") || "n/a"}: ${signal.message}`
  );
  return `Signals:\n${lines.join("\n")}`;
}

function renderMatcherGuidance(signals: Signal[]): string {
  if (signals.length === 0) return "Matcher guidance: none.";
  const lines = unique(signals.map((signal) => signal.slug)).slice(0, 20).map((slug) => {
    const metadata = signalMetadataForSlug(slug);
    return `- ${slug}: check ${metadata.category} evidence, source-to-sink reachability, local mitigation, and whether the finding remains exploitable in the current stage. ${categoryPromptNote(metadata.category)}`;
  });
  return `Matcher guidance:\n${lines.join("\n")}`;
}

function renderSecurityTriageInstructions(input: InvestigationInput): string {
  const tags = input.snapshot.techProfile.tags.join(", ") || "unknown";
  return [
    "Security triage rules:",
    `- Detected stack: ${tags}. Prefer framework-specific mitigations and conventions for this stack.`,
    "- Report only when the code evidence supports source, sink, trust boundary, reachability, and missing or insufficient mitigation.",
    "- Treat broad matcher hits as leads. Reject false positives when the snippet is a test fixture, inert documentation, generated sample, unreachable code, or clearly parameterized/sanitized.",
    "- For auth findings, verify the server-side boundary; client-only checks, hidden buttons, and route names are not enough.",
    "- For injection findings, identify the interpreter or parser sink and why the input can influence it.",
    "- For secret findings, separate live-looking credentials from placeholders, but keep private key material and long provider tokens high risk.",
    "- Include negative evidence when a candidate is mitigated or uncertain instead of stretching weak evidence into a finding."
  ].join("\n");
}

function categoryPromptNote(category: string): string {
  const notes: Record<string, string> = {
    injection: "Prefer concrete data-flow from untrusted input to an interpreter or query sink.",
    auth: "Look for backend authorization at the handler or service boundary, not only UI hiding.",
    secrets: "Distinguish realistic credentials from obvious placeholders, but treat private keys and live-looking tokens as high risk.",
    rce: "Check whether command or code execution receives user-controllable input and whether safe argument APIs are used.",
    ssrf: "Check URL allowlists, internal address blocking, redirect handling, and metadata-service protections.",
    "ai-appsec": "Check untrusted content boundaries, tool authorization, typed argument validation, and prompt disclosure.",
    crypto: "Check whether weak primitives protect sensitive material or are only used for non-security checksums."
  };
  return notes[category] ?? "Prefer specific source evidence over category-level speculation.";
}

function renderGraphSection(graphSummary: unknown): string {
  if (!graphSummary) return "Graph context: none.";
  return `Graph context:\n${JSON.stringify(graphSummary, null, 2).slice(0, 4000)}`;
}

function renderKnowledgeSection(knowledge: RenderedKnowledge): string {
  if (!knowledge.text.trim()) return "Knowledge packs: none.";
  return `Knowledge packs: ${knowledge.packIds.join(", ") || "none"}\n\n${knowledge.text.slice(0, 12000)}`;
}

function renderEvidenceSection(evidence: EvidenceItem[]): string {
  if (evidence.length === 0) return "Evidence: none.";
  return `Evidence:\n${evidence.map((item) => `- ${item.kind} ${item.locator ?? ""}: ${item.summary}`).join("\n").slice(0, 8000)}`;
}

function renderCodeContext(snapshot: ArtifactSnapshot, assets: AssetRecord[], maxChars: number): string {
  const sections: string[] = [];
  let remaining = Math.max(1000, maxChars);
  for (const asset of assets) {
    if (!asset.filePath || remaining <= 0) continue;
    const text = readSafe(snapshot.rootPath, asset.filePath);
    if (!text) continue;
    const excerpt = text.slice(0, Math.min(remaining, 8000));
    sections.push(`### ${asset.filePath}\n\`\`\`\n${excerpt}\n\`\`\``);
    remaining -= excerpt.length;
  }
  return sections.length ? `Code context:\n${sections.join("\n\n")}` : "Code context: none.";
}

function readRepositoryFiles(input: InvestigationInput, source: string, requestedFiles: string[]): { message: string; evidence: EvidenceItem } {
  const allowed = allowedRepositoryFiles(input);
  const selected = unique(requestedFiles.map(normalizeRequestedPath).filter((filePath) => allowed.has(filePath))).slice(0, 6);
  const fallbackFiles = input.assets.map((asset) => asset.filePath).filter((filePath): filePath is string => Boolean(filePath)).slice(0, 4);
  const files = selected.length ? selected : fallbackFiles;
  const snippets = files.map((filePath) => {
    const text = readSafe(input.snapshot.rootPath, filePath);
    return {
      filePath,
      chars: text.length,
      excerpt: text.slice(0, Math.min(6000, Math.max(1000, Math.floor(input.workPacket.budget.maxPromptChars / Math.max(1, files.length)))))
    };
  });
  return {
    message: `Repository read observation:\n${snippets.map((item) => `### ${item.filePath}\n\`\`\`\n${item.excerpt}\n\`\`\``).join("\n\n")}`,
    evidence: repositoryArtifact(input, source, `Repository exploration read ${snippets.length} file(s).`, { files: snippets.map((item) => ({ filePath: item.filePath, chars: item.chars })) })
  };
}

function searchRepository(input: InvestigationInput, source: string, query: string): { message: string; evidence: EvidenceItem } {
  const normalizedQuery = query.trim().slice(0, 160);
  const needles = normalizedQuery
    ? normalizedQuery.toLowerCase().split(/\s+/).filter((token) => token.length >= 3).slice(0, 5)
    : unique(input.signals.map((signal) => signal.slug.split("-")[0] ?? signal.slug)).slice(0, 3);
  const results: Array<{ filePath: string; line: number; text: string }> = [];
  for (const filePath of allowedRepositoryFiles(input)) {
    if (results.length >= 30) break;
    const text = readSafe(input.snapshot.rootPath, filePath);
    const lines = text.split(/\r?\n/);
    lines.forEach((lineText, index) => {
      if (results.length >= 30) return;
      const lower = lineText.toLowerCase();
      if (needles.some((needle) => lower.includes(needle))) {
        results.push({ filePath, line: index + 1, text: lineText.trim().slice(0, 500) });
      }
    });
  }
  return {
    message: `Repository search observation for "${normalizedQuery || needles.join(" ")}":\n${results.map((item) => `- ${item.filePath}:${item.line}: ${item.text}`).join("\n") || "No matches."}`,
    evidence: repositoryArtifact(input, source, `Repository exploration searched for ${normalizedQuery || needles.join(" ")} and found ${results.length} result(s).`, { query: normalizedQuery, results: results.slice(0, 12) })
  };
}

function allowedRepositoryFiles(input: InvestigationInput): Set<string> {
  const files = new Set<string>();
  for (const asset of input.assets) if (asset.filePath) files.add(asset.filePath);
  for (const file of input.snapshot.files) files.add(file.filePath);
  return files;
}

function normalizeRequestedPath(filePath: string): string {
  return filePath.replaceAll("\\", "/").replace(/^\.\//, "");
}

function repositoryArtifact(input: InvestigationInput, source: string, summary: string, raw: unknown): EvidenceItem {
  const primaryAsset = input.assets.find((asset) => asset.id === input.workPacket.primaryAssetId);
  return createEvidence({
    runId: input.snapshot.runId,
    projectId: input.snapshot.projectId,
    candidateId: input.workPacket.candidateIds[0],
    assetId: primaryAsset?.id ?? input.workPacket.primaryAssetId,
    kind: "artifact",
    source,
    summary,
    locator: primaryAsset?.locator,
    raw
  });
}

function readSafe(rootPath: string, filePath: string): string {
  try {
    const resolvedRoot = path.resolve(rootPath);
    const resolvedFile = path.resolve(rootPath, filePath);
    if (!resolvedFile.startsWith(resolvedRoot + path.sep) && resolvedFile !== resolvedRoot) return "";
    if (!fs.existsSync(resolvedFile)) return "";
    return readFileText(rootPath, filePath);
  } catch {
    return "";
  }
}

function parseJsonContent<T>(content: string): T {
  const cleaned = content
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "");
  try {
    return JSON.parse(cleaned) as T;
  } catch {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start >= 0 && end > start) return JSON.parse(cleaned.slice(start, end + 1)) as T;
    throw new Error("Model gateway returned non-JSON content.");
  }
}

function estimateModelUsage(params: {
  input: InvestigationInput;
  model: string;
  provider?: string;
  operation: ModelUsageRecord["operation"];
  promptChars: number;
  responseChars: number;
  attempts: number;
}): ModelUsageRecord {
  const estimatedPromptTokens = Math.ceil(params.promptChars / 4);
  const estimatedResponseTokens = Math.ceil(params.responseChars / 4);
  return {
    id: makeId("usage", [
      params.input.snapshot.runId,
      params.input.workPacket.id,
      params.operation,
      params.model,
      params.promptChars,
      params.responseChars,
      params.attempts
    ]),
    runId: params.input.snapshot.runId,
    projectId: params.input.snapshot.projectId,
    workPacketId: params.input.workPacket.id,
    provider: params.provider,
    model: params.model,
    operation: params.operation,
    promptChars: params.promptChars,
    responseChars: params.responseChars,
    estimatedPromptTokens,
    estimatedResponseTokens,
    estimatedCostUsd: Number(((estimatedPromptTokens * 0.0000005) + (estimatedResponseTokens * 0.0000015)).toFixed(6)),
    attempts: params.attempts,
    createdAt: new Date().toISOString(),
    raw: { estimated: true }
  };
}

function drainUsage(agent: unknown): ModelUsageRecord[] {
  if (!agent || typeof agent !== "object" || typeof (agent as Partial<UsageAwareAgent>).drainUsage !== "function") return [];
  return (agent as UsageAwareAgent).drainUsage();
}

function normalizeAgentError(error: unknown, fallbackMessage: string): AgentExecutionError {
  if (error instanceof AgentExecutionError) return error;
  if (error instanceof Error) {
    return new AgentExecutionError(`${fallbackMessage} ${error.message}`, {
      reason: failureReason(error),
      detail: diagnosticSummary(error),
      retryable: false
    });
  }
  return new AgentExecutionError(`${fallbackMessage} ${String(error)}`, {
    reason: "agent_failure",
    detail: diagnosticSummary(error),
    retryable: false
  });
}

function failureReason(detail: unknown): string {
  if (detail instanceof AgentExecutionError) return detail.reason;
  if (detail instanceof DOMException && detail.name === "AbortError") return "model_timeout";
  if (detail instanceof Error) return detail.name === "AbortError" ? "model_timeout" : "model_gateway_error";
  return "model_gateway_error";
}

function diagnosticSummary(detail: unknown): string {
  if (detail instanceof Error) return `${detail.name}: ${detail.message}`.slice(0, 1000);
  if (typeof detail === "string") return detail.slice(0, 1000);
  try {
    return JSON.stringify(detail).slice(0, 1000);
  } catch {
    return String(detail).slice(0, 1000);
  }
}

interface ProviderRuntimeConfig {
  name?: string;
  baseUrl?: string;
  apiKey?: string;
  apiKeyEnv?: string;
  model: string;
  headers?: Record<string, string>;
  requireApiKey?: boolean;
}

function resolveDefaultProvider(providers?: Record<string, unknown>): ProviderRuntimeConfig | undefined {
  if (!providers) return undefined;
  const candidate = (providers.default ?? providers.openai ?? providers.litellm) as Record<string, unknown> | undefined;
  if (!candidate || typeof candidate !== "object") return undefined;
  const type = typeof candidate.type === "string" ? candidate.type : "openai-compatible";
  if (type !== "openai-compatible" && type !== "litellm" && type !== "openai") return undefined;
  const model =
    stringValue(candidate.defaultModel) ??
    stringValue(candidate.model) ??
    process.env.PROOFSTRIKE_MODEL ??
    "gpt-5.4-mini";
  const headers = recordOfStrings(candidate.headers);
  return {
    name: typeof candidate.name === "string" ? candidate.name : type,
    baseUrl: stringValue(candidate.baseUrl),
    apiKey: stringValue(candidate.apiKey),
    apiKeyEnv: stringValue(candidate.apiKeyEnv) ?? "OPENAI_API_KEY",
    model,
    headers,
    requireApiKey: typeof candidate.requireApiKey === "boolean" ? candidate.requireApiKey : true
  };
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function recordOfStrings(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== "object") return undefined;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter((entry): entry is [string, string] => typeof entry[1] === "string");
  return entries.length ? Object.fromEntries(entries) : undefined;
}
