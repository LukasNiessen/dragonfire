import path from "node:path";

export interface CommandPlan {
  binary: string;
  args: string[];
  cwd?: string;
  rootPath?: string;
}

export interface CommandSandboxDecision {
  allowed: boolean;
  reason?: string;
}

export class CommandSandboxPolicy {
  constructor(private readonly allowedBinaries = new Set(["semgrep", "trivy", "codeql"])) {}

  validate(plan: CommandPlan): CommandSandboxDecision {
    const binaryName = path.basename(plan.binary).toLowerCase().replace(/\.exe$/i, "");
    if (!this.allowedBinaries.has(binaryName)) {
      return { allowed: false, reason: `${plan.binary} is not an approved security tool binary.` };
    }
    if (/[;&|<>`$]/.test(plan.binary)) {
      return { allowed: false, reason: "Binary name contains shell metacharacters." };
    }
    for (const arg of plan.args) {
      if (arg.includes("\0")) return { allowed: false, reason: "Argument contains a null byte." };
      if (/[\r\n]/.test(arg)) return { allowed: false, reason: "Argument contains a newline." };
    }
    if (plan.rootPath && plan.cwd) {
      const root = path.resolve(plan.rootPath);
      const cwd = path.resolve(plan.cwd);
      const relative = path.relative(root, cwd);
      if (relative.startsWith("..") || path.isAbsolute(relative)) {
        return { allowed: false, reason: "Working directory is outside the reviewed repository." };
      }
    }
    return { allowed: true };
  }
}

export const DEFAULT_COMMAND_SANDBOX = new CommandSandboxPolicy();
