import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function makeTempProject(name = "proofstrike-test"): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `${name}-`));
}

export function copyFixture(source: string, target: string): void {
  fs.cpSync(source, target, { recursive: true });
}
