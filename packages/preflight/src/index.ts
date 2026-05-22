import fs from "node:fs";
import path from "node:path";
import { type ProofstrikeConfig, ensureDir, writeJson } from "../../core/src/index.js";
import { loadMatcherPackRefs } from "../../scanner/src/custom.js";
import { createDefaultExternalToolRegistry } from "../../tools/src/index.js";
import type { StagePlan } from "../../stages/src/index.js";

export interface PreflightIssue {
  level: "error" | "warning" | "info";
  code: string;
  message: string;
  remediation?: string;
}

export interface PreflightReport {
  ok: boolean;
  issues: PreflightIssue[];
}

export async function runPreflight(params: {
  rootPath: string;
  config: ProofstrikeConfig;
  stagePlan?: StagePlan;
  requireModel?: boolean;
  requireWritableStore?: boolean;
  externalToolsEnabled?: boolean;
}): Promise<PreflightReport> {
  const issues: PreflightIssue[] = [];
  const root = path.resolve(params.rootPath);
  if (!fs.existsSync(root)) {
    issues.push({
      level: "error",
      code: "root_not_found",
      message: `Project root does not exist: ${root}`
    });
    return report(issues);
  }
  if (params.requireWritableStore ?? true) {
    const dataPath = path.resolve(root, params.config.dataPath || ".proofstrike/proofstrike-data.json");
    try {
      ensureDir(path.dirname(dataPath));
      const probe = path.join(path.dirname(dataPath), `.preflight-${process.pid}.json`);
      writeJson(probe, { ok: true });
      fs.unlinkSync(probe);
    } catch (error) {
      issues.push({
        level: "error",
        code: "store_not_writable",
        message: `Evidence store directory is not writable: ${path.dirname(dataPath)}`,
        remediation: error instanceof Error ? error.message : String(error)
      });
    }
  }

  try {
    loadMatcherPackRefs(root, params.config.packs ?? []);
  } catch (error) {
    issues.push({
      level: "error",
      code: "matcher_pack_invalid",
      message: "One or more configured matcher packs could not be loaded.",
      remediation: error instanceof Error ? error.message : String(error)
    });
  }

  const provider = defaultProvider(params.config.providers);
  const modelRequired = params.requireModel || Boolean(provider);
  if (modelRequired && provider?.requireApiKey !== false) {
    const apiKeyEnv = stringValue(provider?.apiKeyEnv);
    const apiKey = stringValue(provider?.apiKey) || stringValue(apiKeyEnv ? process.env[apiKeyEnv] : undefined);
    if (!apiKey) {
      issues.push({
        level: "error",
        code: "model_credentials_missing",
        message: `Configured model provider requires credentials (${apiKeyEnv ?? "apiKey"}).`,
        remediation: "Set the configured API key environment variable or use runtime.modelFailureMode=static-fallback intentionally."
      });
    }
  }
  if (!provider && params.requireModel) {
    issues.push({
      level: "error",
      code: "model_provider_missing",
      message: "This CI gate requires a model provider, but no providers.default/openai/litellm entry is configured."
    });
  }

  if (params.stagePlan && params.externalToolsEnabled) {
    const registry = createDefaultExternalToolRegistry();
    for (const toolId of params.stagePlan.tools.external) {
      const tool = registry.get(toolId);
      if (!tool) {
        issues.push({
          level: "warning",
          code: "external_tool_unknown",
          message: `Configured external tool is not registered: ${toolId}`
        });
        continue;
      }
      const availability = await tool.isAvailable();
      if (!availability.available) {
        issues.push({
          level: "warning",
          code: "external_tool_unavailable",
          message: `${tool.displayName} is configured for this stage but unavailable.`,
          remediation: availability.reason
        });
      }
    }
  }

  return report(issues);
}

function report(issues: PreflightIssue[]): PreflightReport {
  return {
    ok: !issues.some((issue) => issue.level === "error"),
    issues
  };
}

function defaultProvider(providers?: Record<string, unknown>): Record<string, unknown> | undefined {
  return (providers?.default ?? providers?.openai ?? providers?.litellm) as Record<string, unknown> | undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
