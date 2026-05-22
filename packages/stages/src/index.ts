import {
  STAGES,
  type ProofstrikeConfig,
  type ProjectHistorySummary,
  type StageName,
  deepMerge,
  makeId,
  nowIso
} from "../../core/src/index.js";

export type ScopeMode = "diff" | "diff_plus_context" | "focused_full" | "broad_full" | "deep_full" | "campaign";
export type MatcherProfile = "strict" | "balanced" | "broad" | "research";

export interface StagePreset {
  name: StageName;
  scopeMode: ScopeMode;
  matcherProfile: MatcherProfile;
  graphRadius: number;
  maxFiles: number | "unlimited";
  maxWorkPackets: number | "unlimited";
  maxCostUsd: number;
  validators: {
    enabled: boolean;
    mode: "none" | "light" | "adversarial";
  };
  tools: {
    external: string[];
  };
  policy: {
    failMode: "none" | "warn" | "conservative" | "validated-high" | "release-gate" | "manual";
  };
}

export interface ReviewEvent {
  type?: string;
  stage?: StageName;
  branch?: string;
}

export interface StagePlan extends StagePreset {
  id: string;
  projectId: string;
  event: ReviewEvent;
  historySummary: {
    openFindings: number;
    findingCount: number;
  };
  resolvedAt: string;
}

export const STAGE_PRESETS: Record<StageName, StagePreset> = Object.freeze({
  local: {
    name: "local",
    scopeMode: "diff",
    matcherProfile: "strict",
    graphRadius: 0,
    maxFiles: 40,
    maxWorkPackets: 4,
    maxCostUsd: 0,
    validators: { enabled: false, mode: "none" },
    tools: { external: [] },
    policy: { failMode: "none" }
  },
  pull_request: {
    name: "pull_request",
    scopeMode: "diff_plus_context",
    matcherProfile: "strict",
    graphRadius: 1,
    maxFiles: 120,
    maxWorkPackets: 10,
    maxCostUsd: 2,
    validators: { enabled: true, mode: "light" },
    tools: { external: [] },
    policy: { failMode: "conservative" }
  },
  dev: {
    name: "dev",
    scopeMode: "focused_full",
    matcherProfile: "strict",
    graphRadius: 1,
    maxFiles: 2000,
    maxWorkPackets: 40,
    maxCostUsd: 10,
    validators: { enabled: true, mode: "light" },
    tools: { external: ["semgrep", "trivy"] },
    policy: { failMode: "warn" }
  },
  stage: {
    name: "stage",
    scopeMode: "broad_full",
    matcherProfile: "balanced",
    graphRadius: 2,
    maxFiles: 5000,
    maxWorkPackets: 80,
    maxCostUsd: 25,
    validators: { enabled: true, mode: "adversarial" },
    tools: { external: ["semgrep", "trivy", "codeql"] },
    policy: { failMode: "validated-high" }
  },
  preprod: {
    name: "preprod",
    scopeMode: "deep_full",
    matcherProfile: "broad",
    graphRadius: 2,
    maxFiles: "unlimited",
    maxWorkPackets: 160,
    maxCostUsd: 100,
    validators: { enabled: true, mode: "adversarial" },
    tools: { external: ["semgrep", "trivy", "codeql"] },
    policy: { failMode: "release-gate" }
  },
  campaign: {
    name: "campaign",
    scopeMode: "campaign",
    matcherProfile: "research",
    graphRadius: 3,
    maxFiles: "unlimited",
    maxWorkPackets: "unlimited",
    maxCostUsd: 250,
    validators: { enabled: true, mode: "adversarial" },
    tools: { external: ["semgrep", "trivy", "codeql"] },
    policy: { failMode: "manual" }
  }
});

export class StageResolver {
  constructor(private readonly presets: Record<StageName, StagePreset> = STAGE_PRESETS) {}

  resolve(params: {
    event?: ReviewEvent;
    config: ProofstrikeConfig;
    cliOverrides?: { stage?: StageName; stageConfig?: Partial<StagePreset> };
    history?: ProjectHistorySummary;
  }): StagePlan {
    const event = params.event ?? {};
    const cliOverrides = params.cliOverrides ?? {};
    const name = cliOverrides.stage ?? event.stage ?? inferStage(event, params.config);
    if (!STAGES.includes(name)) {
      throw new Error(`Unknown stage "${name}". Expected one of: ${STAGES.join(", ")}.`);
    }
    const preset = this.presets[name];
    const configured = (params.config.stages?.[name] ?? {}) as Partial<StagePreset>;
    const merged = deepMerge<StagePreset>(preset, configured, cliOverrides.stageConfig as Record<string, unknown> | undefined);
    return {
      ...merged,
      id: makeId("stageplan", [params.config.projectId, name, event, cliOverrides]),
      name,
      projectId: params.config.projectId,
      event,
      historySummary: {
        openFindings: params.history?.openFindings ?? 0,
        findingCount: params.history?.findingCount ?? 0
      },
      resolvedAt: nowIso()
    };
  }
}

export function inferStage(event: ReviewEvent = {}, config: Pick<ProofstrikeConfig, "defaultStage">): StageName {
  if (event.type === "pull_request") return "pull_request";
  if (event.type === "tag" || event.branch?.startsWith("release/")) return "preprod";
  if (event.branch === "dev" || event.branch === "develop") return "dev";
  if (event.branch === "stage" || event.branch === "staging") return "stage";
  return config.defaultStage;
}
