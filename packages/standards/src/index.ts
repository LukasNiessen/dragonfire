import type { Finding, PolicyEvaluation, Severity, ValidationVerdict } from "../../core/src/index.js";

export interface ControlMapping {
  standard: "OWASP_TOP_10_2021" | "OWASP_ASVS_4" | "SOC2" | "ISO_27001" | "NIST_800_53";
  controlId: string;
  title: string;
  rationale: string;
}

export interface FindingControlSummary {
  findingId: string;
  title: string;
  category: string;
  severity: Severity;
  controls: ControlMapping[];
  releaseWeight: number;
  policyDecision?: string;
}

export interface ControlReport {
  findings: FindingControlSummary[];
  byStandard: Record<string, number>;
  byControl: Array<{ standard: string; controlId: string; title: string; findings: number }>;
  releaseRisk: {
    score: number;
    level: "low" | "medium" | "high" | "critical";
    blockers: number;
    manualReview: number;
  };
}

const CONTROL_RULES: Array<{
  id: string;
  categories: string[];
  controls: ControlMapping[];
}> = [
  {
    id: "access-control",
    categories: ["auth", "authorization"],
    controls: [
      control("OWASP_TOP_10_2021", "A01", "Broken Access Control", "Authentication or authorization boundary may be incomplete."),
      control("OWASP_ASVS_4", "V4", "Access Control", "Access-control decisions should be enforced server side."),
      control("SOC2", "CC6.1", "Logical Access", "Logical access should be restricted to authorized users."),
      control("ISO_27001", "A.5.15", "Access Control", "Access rules should reflect business and security requirements.")
    ]
  },
  {
    id: "crypto",
    categories: ["crypto"],
    controls: [
      control("OWASP_TOP_10_2021", "A02", "Cryptographic Failures", "Cryptographic primitives or transport guarantees may be weak."),
      control("OWASP_ASVS_4", "V6", "Cryptography", "Sensitive data should use approved cryptographic controls."),
      control("NIST_800_53", "SC-13", "Cryptographic Protection", "Cryptography should protect confidentiality and integrity.")
    ]
  },
  {
    id: "injection",
    categories: ["injection", "xss", "xxe", "deserialization"],
    controls: [
      control("OWASP_TOP_10_2021", "A03", "Injection", "Untrusted input may reach an interpreter, template, parser, or unsafe object boundary."),
      control("OWASP_ASVS_4", "V5", "Validation, Sanitization, and Encoding", "Inputs should be validated and encoded before sensitive sinks."),
      control("NIST_800_53", "SI-10", "Information Input Validation", "Information inputs should be validated before processing.")
    ]
  },
  {
    id: "design",
    categories: ["ai-security", "ai-appsec", "cache", "availability"],
    controls: [
      control("OWASP_TOP_10_2021", "A04", "Insecure Design", "The risky behavior may require architectural mitigation, not only a local patch."),
      control("OWASP_ASVS_4", "V1", "Architecture, Design, and Threat Modeling", "Security-sensitive flows should have explicit design controls."),
      control("SOC2", "CC7.1", "System Operations", "Risky automated behavior should be monitored and controlled.")
    ]
  },
  {
    id: "misconfiguration",
    categories: ["iac", "container", "web-security", "mobile", "desktop", "exposure"],
    controls: [
      control("OWASP_TOP_10_2021", "A05", "Security Misconfiguration", "Configuration may expose services, data, or privileged runtime behavior."),
      control("OWASP_ASVS_4", "V14", "Configuration", "Deployment and framework configuration should be hardened."),
      control("NIST_800_53", "CM-6", "Configuration Settings", "Security configuration settings should be established and monitored.")
    ]
  },
  {
    id: "secrets",
    categories: ["secrets"],
    controls: [
      control("OWASP_TOP_10_2021", "A07", "Identification and Authentication Failures", "Secret exposure can undermine identity and authentication guarantees."),
      control("OWASP_ASVS_4", "V7", "Error Handling and Logging", "Logs and source code should not expose credentials or sensitive data."),
      control("SOC2", "CC6.6", "Confidential Information", "Credentials and confidential data should be protected from unauthorized disclosure.")
    ]
  },
  {
    id: "supply-chain",
    categories: ["supply-chain", "ci-cd"],
    controls: [
      control("OWASP_TOP_10_2021", "A08", "Software and Data Integrity Failures", "Build, package, or dependency integrity may be weak."),
      control("OWASP_ASVS_4", "V14.2", "Dependency Management", "Dependencies and build steps should be trusted and pinned."),
      control("NIST_800_53", "SA-12", "Supply Chain Protection", "Supply-chain risk should be controlled throughout delivery.")
    ]
  },
  {
    id: "ssrf",
    categories: ["ssrf", "open-redirect"],
    controls: [
      control("OWASP_TOP_10_2021", "A10", "Server-Side Request Forgery", "Outbound request targets or redirects may be attacker-controlled."),
      control("OWASP_ASVS_4", "V12", "File and Resources", "Server-side resource access should be constrained and validated."),
      control("NIST_800_53", "SC-7", "Boundary Protection", "Network boundaries should restrict unsafe egress paths.")
    ]
  }
];

export function buildControlReport(params: {
  findings: Finding[];
  validations?: ValidationVerdict[];
  policyDecisions?: PolicyEvaluation[];
}): ControlReport {
  const decisions = new Map((params.policyDecisions ?? []).map((item) => [item.findingId, item]));
  const validations = new Map((params.validations ?? []).map((item) => [item.findingId, item]));
  const findings = params.findings.map((finding) => {
    const controls = controlsForFinding(finding);
    const validation = validations.get(finding.id);
    const decision = decisions.get(finding.id);
    return {
      findingId: finding.id,
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      controls,
      releaseWeight: releaseWeight(finding, validation, decision),
      policyDecision: decision?.decision
    } satisfies FindingControlSummary;
  });
  const byStandard: Record<string, number> = {};
  const controlCounts = new Map<string, { standard: string; controlId: string; title: string; findings: number }>();
  for (const item of findings) {
    for (const mapped of item.controls) {
      byStandard[mapped.standard] = (byStandard[mapped.standard] ?? 0) + 1;
      const key = `${mapped.standard}:${mapped.controlId}`;
      const current = controlCounts.get(key) ?? {
        standard: mapped.standard,
        controlId: mapped.controlId,
        title: mapped.title,
        findings: 0
      };
      current.findings += 1;
      controlCounts.set(key, current);
    }
  }
  const score = findings.reduce((total, item) => total + item.releaseWeight, 0);
  const blockers = params.policyDecisions?.filter((item) => item.decision === "fail").length ?? 0;
  const manualReview = params.policyDecisions?.filter((item) => item.decision === "manual_review").length ?? 0;
  return {
    findings,
    byStandard,
    byControl: [...controlCounts.values()].sort((a, b) => b.findings - a.findings || a.controlId.localeCompare(b.controlId)),
    releaseRisk: {
      score,
      level: riskLevel(score, blockers),
      blockers,
      manualReview
    }
  };
}

export function controlsForFinding(finding: Pick<Finding, "category" | "cwe">): ControlMapping[] {
  const direct = CONTROL_RULES
    .filter((rule) => rule.categories.includes(finding.category))
    .flatMap((rule) => rule.controls);
  const cwe = controlsForCwe(finding.cwe ?? []);
  return uniqueControls([...direct, ...cwe]);
}

function control(
  standard: ControlMapping["standard"],
  controlId: string,
  title: string,
  rationale: string
): ControlMapping {
  return { standard, controlId, title, rationale };
}

function controlsForCwe(cwe: string[]): ControlMapping[] {
  const joined = cwe.join(" ");
  if (/CWE-(?:79|80|116)/.test(joined)) {
    return [control("OWASP_TOP_10_2021", "A03", "Injection", "XSS and output-encoding weaknesses map to injection risk.")];
  }
  if (/CWE-(?:89|90|943)/.test(joined)) {
    return [control("OWASP_TOP_10_2021", "A03", "Injection", "Database query injection maps to input validation and query binding controls.")];
  }
  if (/CWE-(?:22|73)/.test(joined)) {
    return [control("OWASP_ASVS_4", "V12", "File and Resources", "Path traversal maps to constrained resource access.")];
  }
  return [];
}

function releaseWeight(
  finding: Finding,
  validation?: ValidationVerdict,
  decision?: PolicyEvaluation
): number {
  const severity = { info: 0.5, low: 1, medium: 3, high: 7, critical: 12 }[finding.severity] ?? 3;
  const confidence = { low: 0.5, medium: 0.8, high: 1 }[finding.confidence] ?? 0.8;
  const validationBoost = validation?.real.passed === true ? 1.25 : validation?.real.passed === false ? 0.6 : 1;
  const policyBoost = decision?.decision === "fail" ? 1.5 : decision?.decision === "manual_review" ? 1.15 : 1;
  return Number((severity * confidence * validationBoost * policyBoost).toFixed(2));
}

function riskLevel(score: number, blockers: number): ControlReport["releaseRisk"]["level"] {
  if (blockers > 0 || score >= 30) return "critical";
  if (score >= 16) return "high";
  if (score >= 6) return "medium";
  return "low";
}

function uniqueControls(controls: ControlMapping[]): ControlMapping[] {
  const byKey = new Map<string, ControlMapping>();
  for (const item of controls) byKey.set(`${item.standard}:${item.controlId}`, item);
  return [...byKey.values()];
}
