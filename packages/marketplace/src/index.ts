import fs from "node:fs";
import path from "node:path";
import { ensureDir, readJsonIfExists, writeJson, makeId, nowIso } from "../../core/src/index.js";

export interface InstalledPack {
  id: string;
  version: string;
  source: string;
  installedAt: string;
  digest: string;
}

export class PackManager {
  private readonly manifestPath: string;

  constructor(private readonly rootPath: string) {
    this.manifestPath = path.join(rootPath, ".proofstrike", "packs.json");
  }

  list(): InstalledPack[] {
    return readJsonIfExists<InstalledPack[]>(this.manifestPath, []);
  }

  install(ref: string): InstalledPack {
    ensureDir(path.dirname(this.manifestPath));
    const current = this.list();
    const pack: InstalledPack = {
      id: packIdFromRef(ref),
      version: "local",
      source: ref,
      installedAt: nowIso(),
      digest: makeId("pack", [ref])
    };
    const next = current.filter((item) => item.id !== pack.id);
    next.push(pack);
    writeJson(this.manifestPath, next);
    return pack;
  }

  audit(): { ok: boolean; issues: string[] } {
    const issues: string[] = [];
    for (const pack of this.list()) {
      if (!pack.id || !pack.source) issues.push(`Invalid pack record: ${JSON.stringify(pack)}`);
      if (pack.source.startsWith(".") || path.isAbsolute(pack.source)) {
        const absolute = path.resolve(this.rootPath, pack.source);
        if (!fs.existsSync(absolute)) issues.push(`Local pack path does not exist: ${pack.source}`);
      }
    }
    return { ok: issues.length === 0, issues };
  }
}

function packIdFromRef(ref: string): string {
  return ref
    .replace(/^github:/, "")
    .replace(/^npm:/, "")
    .replace(/[^A-Za-z0-9_.@/-]+/g, "-")
    .replace(/[\/\\]/g, ".")
    .replace(/^@/, "")
    .toLowerCase();
}
