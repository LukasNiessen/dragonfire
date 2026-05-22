import fs from "node:fs";
import path from "node:path";
import {
  type AssetRecord,
  type EvidenceItem,
  type Finding,
  type PolicyEvaluation,
  type ProofstrikeConfig,
  type Signal,
  type ValidationVerdict,
  ensureDir,
  writeJson
} from "../../core/src/index.js";
import type { ReviewResult } from "../../orchestrator/src/index.js";

export interface ReporterOutput {
  format: string;
  path: string;
  summary: string;
}

export function renderReports(result: ReviewResult, params: {
  rootPath: string;
  config: ProofstrikeConfig;
  formats?: string[];
}): ReporterOutput[] {
  const outDir = path.resolve(params.rootPath, params.config.outputDir || ".proofstrike/reports");
  ensureDir(outDir);
  const outputs: ReporterOutput[] = [];
  for (const format of params.formats ?? ["markdown", "json", "sarif"]) {
    if (format === "json") {
      const filePath = path.join(outDir, `${result.runId}.json`);
      writeJson(filePath, evidenceBundle(result));
      outputs.push({ format, path: filePath, summary: "JSON evidence bundle" });
    }
    if (format === "markdown") {
      const filePath = path.join(outDir, `${result.runId}.md`);
      fs.writeFileSync(filePath, renderMarkdown(result), "utf8");
      outputs.push({ format, path: filePath, summary: "Markdown report" });
    }
    if (format === "sarif") {
      const filePath = path.join(outDir, `${result.runId}.sarif`);
      writeJson(filePath, renderSarif(result));
      outputs.push({ format, path: filePath, summary: "SARIF report" });
    }
    if (format === "pr-comment") {
      const filePath = path.join(outDir, `${result.runId}.pr-comment.md`);
      fs.writeFileSync(filePath, renderPrComment(result), "utf8");
      outputs.push({ format, path: filePath, summary: "PR comment markdown" });
    }
  }
  return outputs;
}

export interface ReportLike {
  runId: string;
  stagePlan: { name: string };
  snapshot: { scopedFileCount: number };
  signals: Signal[];
  findings: Finding[];
  validations: ValidationVerdict[];
  policyDecisions: PolicyEvaluation[];
  assets: AssetRecord[];
  evidence?: EvidenceItem[];
}

export function evidenceBundle(result: ReportLike): Record<string, unknown> {
  return {
    schemaVersion: 1,
    runId: result.runId,
    stage: result.stagePlan.name,
    stats: {
      files: result.snapshot.scopedFileCount,
      signals: result.signals.length,
      findings: result.findings.length,
      validations: result.validations.length
    },
    findings: result.findings,
    validations: result.validations,
    policyDecisions: result.policyDecisions,
    signals: result.signals,
    evidence: result.evidence ?? []
  };
}

export function renderMarkdown(result: ReportLike): string {
  const lines: string[] = [];
  lines.push("# Proofstrike Report");
  lines.push("");
  lines.push(`Run: \`${result.runId}\``);
  lines.push(`Stage: \`${result.stagePlan.name}\``);
  lines.push(`Files reviewed: ${result.snapshot.scopedFileCount}`);
  lines.push(`Signals: ${result.signals.length}`);
  lines.push(`Findings: ${result.findings.length}`);
  lines.push("");
  if (result.findings.length === 0) {
    lines.push("No findings were produced.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }
  for (const finding of result.findings) {
    const decision = result.policyDecisions.find((item) => item.findingId === finding.id);
    const validation = result.validations.find((item) => item.findingId === finding.id);
    lines.push(`## ${finding.title}`);
    lines.push("");
    lines.push(`- Severity: \`${finding.severity}\``);
    lines.push(`- Confidence: \`${finding.confidence}\``);
    lines.push(`- Evidence level: \`${finding.evidenceLevel}\``);
    lines.push(`- Policy: \`${decision?.decision || "warn"}\` - ${decision?.reason || "No policy decision."}`);
    lines.push(`- Lines: ${finding.lineNumbers.length ? finding.lineNumbers.join(", ") : "n/a"}`);
    lines.push("");
    lines.push(finding.summary);
    lines.push("");
    lines.push("Technical details:");
    lines.push("");
    lines.push(finding.technicalDetails);
    lines.push("");
    if (validation) {
      lines.push("Validation:");
      lines.push("");
      lines.push(`- Real: \`${validation.real.passed}\` - ${validation.real.rationale}`);
      lines.push(`- Reachable: \`${validation.reachable.passed}\` - ${validation.reachable.rationale}`);
      lines.push(`- Impactful: \`${validation.impactful.passed}\` - ${validation.impactful.rationale}`);
      lines.push("");
    }
    lines.push("Recommendation:");
    lines.push("");
    lines.push(finding.recommendation);
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

export function renderPrComment(result: ReportLike): string {
  const blocking = result.policyDecisions.filter((item) => item.decision === "fail");
  const review = result.policyDecisions.filter((item) => item.decision === "manual_review");
  const warn = result.policyDecisions.filter((item) => item.decision === "warn");
  const lines = [
    "## Proofstrike Security Review",
    "",
    `Stage: \`${result.stagePlan.name}\``,
    `Signals: ${result.signals.length} | Findings: ${result.findings.length}`,
    `Policy: ${blocking.length} fail, ${review.length} manual review, ${warn.length} warn`,
    ""
  ];
  for (const finding of result.findings.slice(0, 10)) {
    const decision = result.policyDecisions.find((item) => item.findingId === finding.id);
    lines.push(`- **${finding.title}** (${finding.severity}, ${decision?.decision || "warn"}): ${finding.summary}`);
  }
  if (result.findings.length > 10) lines.push(`- ... and ${result.findings.length - 10} more finding(s).`);
  return `${lines.join("\n")}\n`;
}

export function renderSarif(result: ReportLike): Record<string, unknown> {
  const rulesById = new Map<string, Record<string, unknown>>();
  const results: Record<string, unknown>[] = [];
  for (const finding of result.findings) {
    rulesById.set(finding.category, {
      id: finding.category,
      name: finding.category,
      shortDescription: { text: finding.category },
      help: { text: finding.recommendation }
    });
    const asset = result.assets.find((item) => item.id === finding.primaryAssetId);
    results.push({
      ruleId: finding.category,
      level: sarifLevel(finding.severity),
      message: { text: `${finding.title}: ${finding.summary}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: asset?.filePath || asset?.locator || "unknown" },
            region: {
              startLine: finding.lineNumbers[0] || 1
            }
          }
        }
      ],
      partialFingerprints: {
        proofstrikeFingerprint: finding.fingerprint
      },
      properties: {
        confidence: finding.confidence,
        evidenceLevel: finding.evidenceLevel,
        recommendation: finding.recommendation
      }
    });
  }
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Proofstrike",
            informationUri: "https://github.com/proofstrike/proofstrike",
            rules: [...rulesById.values()]
          }
        },
        results
      }
    ]
  };
}

function sarifLevel(severity: string): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}
