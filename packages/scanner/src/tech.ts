import { normalizePath } from "../../core/src/index.js";

export interface TechnologyDetector {
  tag: string;
  manifests?: string[];
  files?: RegExp[];
  packageNames?: string[];
  content?: RegExp[];
}

export interface TechnologyDetectionInput {
  files: string[];
  packageDependencies?: Record<string, string>;
  readText?: (filePath: string) => string | undefined;
}

export interface TechnologyDetectionResult {
  tags: string[];
  manifests: string[];
}

export const TECHNOLOGY_DETECTORS: readonly TechnologyDetector[] = Object.freeze([
  { tag: "node", manifests: ["package.json"], packageNames: ["typescript", "tsx", "ts-node"] },
  { tag: "typescript", packageNames: ["typescript"], files: [/\.(?:ts|tsx)$/i] },
  { tag: "react", packageNames: ["react", "react-dom"], files: [/\.(?:jsx|tsx)$/i], content: [/\bReact\b|dangerouslySetInnerHTML/] },
  { tag: "vue", packageNames: ["vue", "nuxt"], files: [/\.vue$/i], content: [/\bv-html\b/] },
  { tag: "angular", packageNames: ["@angular/core"], content: [/\bDomSanitizer\b|bypassSecurityTrust/] },
  { tag: "sveltekit", packageNames: ["@sveltejs/kit"], files: [/\+server\.(?:js|ts)$/i] },
  { tag: "nextjs", packageNames: ["next"], files: [/^app\/.+\/route\.(?:js|ts)$/i, /^pages\/api\//i] },
  { tag: "remix", packageNames: ["@remix-run/node", "@remix-run/react"], content: [/\bexport\s+(?:async\s+)?(?:function\s+)?(?:loader|action)\b/] },
  { tag: "express", packageNames: ["express"], content: [/\bexpress\.Router\b|\bapp\.(?:get|post|put|patch|delete)\s*\(/] },
  { tag: "fastify", packageNames: ["fastify"], content: [/\bfastify\.(?:get|post|put|patch|delete|route)\s*\(/] },
  { tag: "nestjs", packageNames: ["@nestjs/core", "@nestjs/common"], content: [/@(?:Controller|Get|Post|Put|Patch|Delete)\b/] },
  { tag: "hono", packageNames: ["hono"], content: [/\bnew\s+Hono\b|\bapp\.(?:get|post|put|patch|delete)\s*\(/] },
  { tag: "koa", packageNames: ["koa", "@koa/router"], content: [/\bnew\s+Router\b|ctx\.(?:request|body|query)/] },
  { tag: "hapi", packageNames: ["@hapi/hapi"], content: [/\bserver\.route\s*\(/] },
  { tag: "trpc", packageNames: ["@trpc/server"], content: [/\bpublicProcedure\b|\bprotectedProcedure\b/] },
  { tag: "graphql", packageNames: ["graphql", "@apollo/server", "apollo-server"], content: [/\btypeDefs\b|\bresolvers\b|GraphQLObjectType/] },
  { tag: "prisma", packageNames: ["@prisma/client", "prisma"], files: [/^prisma\/schema\.prisma$/i] },
  { tag: "sequelize", packageNames: ["sequelize"], content: [/\bSequelize\b|sequelize\.query/] },
  { tag: "mongoose", packageNames: ["mongoose"], content: [/\bmongoose\.(?:model|connect)\b/] },
  { tag: "electron", packageNames: ["electron"], content: [/\bBrowserWindow\b|nodeIntegration|contextIsolation/] },
  { tag: "python", manifests: ["requirements.txt", "pyproject.toml", "Pipfile"], files: [/\.py$/i] },
  { tag: "django", packageNames: ["django"], content: [/\bDJANGO_SETTINGS_MODULE\b|from django\b|@csrf_exempt/] },
  { tag: "flask", packageNames: ["flask"], content: [/\bFlask\s*\(|@\w+\.route\s*\(/] },
  { tag: "fastapi", packageNames: ["fastapi"], content: [/\bFastAPI\s*\(|@\w+\.(?:get|post|put|patch|delete)\s*\(/] },
  { tag: "celery", packageNames: ["celery"], content: [/\bCelery\s*\(|@(?:app|shared)_task\b/] },
  { tag: "rails", files: [/^config\/routes\.rb$/i, /^app\/controllers\//i], content: [/\bApplicationController\b|skip_before_action/] },
  { tag: "sinatra", content: [/\bSinatra::Base\b|(?:get|post|put|delete)\s+["']\//] },
  { tag: "ruby", manifests: ["Gemfile"], files: [/\.rb$/i] },
  { tag: "go", manifests: ["go.mod"], files: [/\.go$/i] },
  { tag: "gin", content: [/\bgin\.(?:Default|New|Context)\b|\*gin\.Context/] },
  { tag: "echo", content: [/\becho\.New\s*\(/] },
  { tag: "fiber", content: [/\bfiber\.New\s*\(/] },
  { tag: "rust", manifests: ["Cargo.toml"], files: [/\.rs$/i] },
  { tag: "axum", content: [/\baxum::|Router::new\(\)\.route|\bJson\s*</] },
  { tag: "actix", content: [/\bactix_web\b|HttpServer::new/] },
  { tag: "java", manifests: ["pom.xml"], files: [/\.java$/i] },
  { tag: "kotlin", manifests: ["build.gradle.kts"], files: [/\.kt$/i] },
  { tag: "spring", content: [/@(?:RestController|Controller|RequestMapping|GetMapping|PostMapping)\b|management\.endpoints\.web/] },
  { tag: "jvm", manifests: ["pom.xml", "build.gradle", "build.gradle.kts"], files: [/\.(?:java|kt|scala)$/i] },
  { tag: "dotnet", files: [/\.(?:cs|csproj|fsproj|vbproj)$/i], content: [/\bWebApplication\.CreateBuilder\b|\[ApiController\]/] },
  { tag: "php", manifests: ["composer.json"], files: [/\.php$/i] },
  { tag: "laravel", content: [/\bRoute::(?:get|post|put|patch|delete)\b|\$request->all\(\)/] },
  { tag: "symfony", content: [/\bSymfony\\Component\b|#\[\s*Route\(/] },
  { tag: "terraform", files: [/\.tf$/i] },
  { tag: "kubernetes", files: [/(?:^|\/)k8s\/.*\.ya?ml$/i, /(?:^|\/)manifests\/.*\.ya?ml$/i], content: [/\bapiVersion:\s*(?:apps\/v1|v1|networking\.k8s\.io)/] },
  { tag: "github-actions", files: [/^\.github\/workflows\/.+\.ya?ml$/i] },
  { tag: "jenkins", files: [/^Jenkinsfile$/i] },
  { tag: "docker", files: [/(?:^|\/)Dockerfile$/i, /docker-compose\.ya?ml$/i] },
  { tag: "android", files: [/AndroidManifest\.xml$/i, /build\.gradle$/i] },
  { tag: "ios", files: [/Info\.plist$/i, /\.swift$/i] },
  { tag: "ai-app", packageNames: ["openai", "@anthropic-ai/sdk", "langchain", "@langchain/core", "ai"], content: [/\b(?:system|developer)\s*:\s*["'`]|tool_calls|function_call|messages\s*:/] }
]);

export function detectTechnology(input: TechnologyDetectionInput): TechnologyDetectionResult {
  const files = input.files.map(normalizePath);
  const fileSet = new Set(files);
  const dependencies = new Set(Object.keys(input.packageDependencies ?? {}));
  const tags = new Set<string>();
  const manifests = new Set<string>();
  const sampledText = new Map<string, string>();

  for (const detector of TECHNOLOGY_DETECTORS) {
    const manifestMatches = (detector.manifests ?? []).filter((manifest) => fileSet.has(normalizePath(manifest)));
    const fileMatches = (detector.files ?? []).some((pattern) => files.some((file) => pattern.test(file)));
    const packageMatches = (detector.packageNames ?? []).some((name) => dependencies.has(name));
    const contentMatches = (detector.content ?? []).some((pattern) =>
      files.some((file) => {
        if (!input.readText) return false;
        let text = sampledText.get(file);
        if (text === undefined) {
          text = input.readText(file) ?? "";
          sampledText.set(file, text.slice(0, 24000));
        }
        return pattern.test(text);
      })
    );
    if (manifestMatches.length || fileMatches || packageMatches || contentMatches) {
      tags.add(detector.tag);
      for (const manifest of manifestMatches) manifests.add(manifest);
    }
  }

  return {
    tags: [...tags].sort(),
    manifests: [...manifests].sort()
  };
}
