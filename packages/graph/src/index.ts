import {
  type AssetRecord,
  makeId,
  normalizePath
} from "../../core/src/index.js";
import { type ArtifactSnapshot, type FileAsset, readFileText } from "../../ingest/src/index.js";
import type { WorkPacket } from "../../core/src/index.js";

export interface RouteAsset extends AssetRecord {
  type: "route";
  filePath: string;
  fileAssetId: string;
  method: string;
  path: string;
}

export interface ImportEdge {
  fromAssetId: string;
  toAssetId: string;
  kind: "imports";
  rawTarget: string;
}

export interface CodeIndex {
  projectId: string;
  runId: string;
  routes: RouteAsset[];
  imports: ImportEdge[];
  authHints: string[];
  assetsByPath: Map<string, FileAsset>;
}

export class CodeIndexer {
  async index(snapshot: ArtifactSnapshot): Promise<CodeIndex> {
    const routes: RouteAsset[] = [];
    const imports: ImportEdge[] = [];
    const authHints: string[] = [];
    for (const file of snapshot.files) {
      const text = readFileText(snapshot.rootPath, file.filePath);
      routes.push(...extractRoutes({ projectId: snapshot.projectId, runId: snapshot.runId, file, text }));
      imports.push(...extractImports(file, text));
      if (hasAuthBoundary(text)) authHints.push(file.id);
    }
    return {
      projectId: snapshot.projectId,
      runId: snapshot.runId,
      routes,
      imports,
      authHints,
      assetsByPath: new Map(snapshot.files.map((asset) => [asset.filePath, asset]))
    };
  }
}

export class GraphExpander {
  expandCandidates<T extends { primaryAssetId: string; relatedAssetIds: string[] }>(params: {
    candidates: T[];
    codeIndex: CodeIndex;
    stagePlan: { graphRadius: number };
  }): T[] {
    return params.candidates.map((candidate) => this.expandOne(candidate, {
      codeIndex: params.codeIndex,
      radius: params.stagePlan.graphRadius || 0
    }));
  }

  expandOne<T extends { primaryAssetId: string; relatedAssetIds: string[] }>(candidate: T, params: {
    codeIndex: CodeIndex;
    radius: number;
  }): T {
    if (params.radius <= 0) return candidate;
    const related = new Set(candidate.relatedAssetIds);
    related.add(candidate.primaryAssetId);
    for (const route of params.codeIndex.routes) {
      if (route.fileAssetId === candidate.primaryAssetId) related.add(route.id);
    }
    for (const edge of params.codeIndex.imports) {
      if (edge.fromAssetId === candidate.primaryAssetId) related.add(edge.toAssetId);
      if (edge.toAssetId === candidate.primaryAssetId) related.add(edge.fromAssetId);
    }
    if (params.radius > 1) {
      for (const authAssetId of params.codeIndex.authHints) related.add(authAssetId);
    }
    return {
      ...candidate,
      relatedAssetIds: [...related]
    };
  }
}

export function graphSummaryForPacket(packet: WorkPacket, codeIndex: CodeIndex): {
  routeCount: number;
  routes: string[];
  authBoundaryFiles: number;
} {
  const routes = codeIndex.routes.filter((route) => packet.assetIds.includes(route.fileAssetId) || packet.assetIds.includes(route.id));
  return {
    routeCount: routes.length,
    routes: routes.slice(0, 10).map((route) => `${route.method} ${route.path} (${route.filePath})`),
    authBoundaryFiles: codeIndex.authHints.length
  };
}

export function extractRoutes(params: {
  projectId: string;
  runId: string;
  file: FileAsset;
  text: string;
}): RouteAsset[] {
  const routes: RouteAsset[] = [];
  const filePath = normalizePath(params.file.filePath);
  const routeRegexes: Array<{ re: RegExp; methodIndex: number; pathIndex?: number }> = [
    { re: /(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/gi, methodIndex: 1, pathIndex: 2 },
    { re: /export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(/g, methodIndex: 1 }
  ];
  for (const { re, methodIndex, pathIndex } of routeRegexes) {
    for (const match of params.text.matchAll(re)) {
      const method = String(match[methodIndex] || "GET").toUpperCase();
      const routePath = pathIndex ? String(match[pathIndex]) : routePathFromFile(filePath);
      routes.push(createRouteAsset({ ...params, filePath, method, routePath }));
    }
  }
  if (routes.length === 0 && filePath.includes("/api/")) {
    routes.push(createRouteAsset({ ...params, filePath, method: "ANY", routePath: routePathFromFile(filePath), inferred: true }));
  }
  return routes;
}

function createRouteAsset(params: {
  projectId: string;
  runId: string;
  file: FileAsset;
  filePath: string;
  method: string;
  routePath: string;
  inferred?: boolean;
}): RouteAsset {
  return {
    id: makeId("asset", [params.projectId, "route", params.method, params.routePath, params.filePath]),
    projectId: params.projectId,
    type: "route",
    locator: `${params.method} ${params.routePath}`,
    displayName: `${params.method} ${params.routePath}`,
    fingerprint: makeId("routefp", [params.method, params.routePath, params.filePath]),
    filePath: params.filePath,
    fileAssetId: params.file.id,
    method: params.method,
    path: params.routePath,
    frameworkTags: [],
    owners: [],
    sensitivity: [],
    metadata: params.inferred ? { inferred: true } : {},
    firstSeenRunId: params.runId,
    lastSeenRunId: params.runId,
    status: "active"
  };
}

function extractImports(file: FileAsset, text: string): ImportEdge[] {
  const edges: ImportEdge[] = [];
  const imports = [...text.matchAll(/(?:import\s+.*?from\s+["']([^"']+)["']|require\(["']([^"']+)["']\))/g)];
  for (const match of imports) {
    const target = match[1] || match[2];
    if (!target?.startsWith(".")) continue;
    edges.push({
      fromAssetId: file.id,
      toAssetId: makeId("asset", [file.projectId, "file", normalizePath(target)]),
      kind: "imports",
      rawTarget: target
    });
  }
  return edges;
}

function hasAuthBoundary(text: string): boolean {
  return /\b(?:requireAuth|requireUser|requireAdmin|authorize|permission|role|session|jwt|verifyToken)\b/i.test(text);
}

function routePathFromFile(filePath: string): string {
  const normalized = normalizePath(filePath);
  const apiIndex = normalized.indexOf("/api/");
  const route = apiIndex >= 0 ? normalized.slice(apiIndex + 4) : `/${normalized}`;
  return `/${route.replace(/\.(js|jsx|ts|tsx|py|rb)$/i, "").replace(/\/index$/i, "")}`;
}
