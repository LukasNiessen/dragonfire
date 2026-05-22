import type { Finding, PolicyEvaluation } from "../../core/src/index.js";
import type { MatcherPlugin } from "../../scanner/src/index.js";
import type { InvestigatorAgent, ValidatorAgent } from "../../agents/src/index.js";

export interface OwnershipRecord {
  owners: string[];
  escalation?: string[];
  source?: string;
  raw?: unknown;
}

export interface OwnershipProvider {
  name: string;
  fetchOwnership(params: { filePath: string; rootPath: string; projectId: string }): Promise<OwnershipRecord | null>;
}

export interface NotificationRecord {
  notifierName: string;
  findingId: string;
  notifiedAt: string;
  externalId?: string;
  externalUrl?: string;
  raw?: unknown;
}

export interface NotifierProvider {
  name: string;
  notify(params: {
    finding: Finding;
    policy?: PolicyEvaluation;
    projectId: string;
    rootPath: string;
  }): Promise<NotificationRecord>;
}

export interface ExecutorLaunchRequest {
  projectId: string;
  command: "ci" | "review" | "revalidate" | "triage" | "report";
  files: string[];
  parallelism?: number;
  timeoutMs?: number;
  env?: Record<string, string>;
  options?: Record<string, unknown>;
}

export interface ExecutorStatus {
  runId: string;
  state: "queued" | "running" | "done" | "error";
  message?: string;
}

export interface ExecutorProvider {
  name: string;
  launch(request: ExecutorLaunchRequest, onLog?: (message: string) => void): Promise<string>;
  collect(runId: string): Promise<void>;
  status?(runId: string): Promise<ExecutorStatus>;
}

export interface AgentProvider {
  name: string;
  investigator?: InvestigatorAgent;
  validator?: ValidatorAgent;
}

export interface ProofstrikeExtension {
  name: string;
  matchers?: MatcherPlugin[];
  ownership?: OwnershipProvider;
  notifiers?: NotifierProvider[];
  executor?: ExecutorProvider;
  agents?: AgentProvider[];
}

export class ExtensionRegistry {
  private readonly extensions: ProofstrikeExtension[] = [];

  constructor(extensions: ProofstrikeExtension[] = []) {
    for (const extension of extensions) this.register(extension);
  }

  register(extension: ProofstrikeExtension): void {
    if (!extension.name) throw new Error("Extension must have a name.");
    this.extensions.push(extension);
  }

  all(): ProofstrikeExtension[] {
    return [...this.extensions];
  }

  matchers(): MatcherPlugin[] {
    return this.extensions.flatMap((extension) => extension.matchers ?? []);
  }

  ownership(): OwnershipProvider | undefined {
    return [...this.extensions].reverse().find((extension) => extension.ownership)?.ownership;
  }

  notifiers(): NotifierProvider[] {
    return this.extensions.flatMap((extension) => extension.notifiers ?? []);
  }

  executor(): ExecutorProvider | undefined {
    return [...this.extensions].reverse().find((extension) => extension.executor)?.executor;
  }

  agents(): AgentProvider[] {
    return this.extensions.flatMap((extension) => extension.agents ?? []);
  }
}

export class LocalExecutorProvider implements ExecutorProvider {
  name = "local";
  private readonly statuses = new Map<string, ExecutorStatus>();

  async launch(request: ExecutorLaunchRequest, onLog: (message: string) => void = () => undefined): Promise<string> {
    const runId = `local-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    this.statuses.set(runId, {
      runId,
      state: "queued",
      message: `${request.command} queued for ${request.files.length} file(s)`
    });
    onLog(`local executor accepted ${request.command} with ${request.files.length} file(s)`);
    this.statuses.set(runId, {
      runId,
      state: "done",
      message: "Local executor is an in-process coordination boundary; the caller performs the run."
    });
    return runId;
  }

  async collect(_runId: string): Promise<void> {
    return;
  }

  async status(runId: string): Promise<ExecutorStatus> {
    return this.statuses.get(runId) ?? { runId, state: "error", message: "Unknown local executor run." };
  }
}
