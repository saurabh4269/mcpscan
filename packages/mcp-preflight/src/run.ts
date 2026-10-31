import { probeAuth } from "./auth.js";
import { buildDirectoryChecklist } from "./directory.js";
import { scanToolText } from "./injection.js";
import { listMcpTools } from "./mcp-client.js";
import { heuristicToolsFromRepo, parseGithubRepoUrl, scanGithubRepo } from "./repo.js";
import { buildFixList, computeScore } from "./score.js";
import { buildToolsReport } from "./tools-report.js";
import type { PreflightReport } from "./types.js";

export interface PreflightInput {
  repoUrl?: string;
  mcpUrl?: string;
}

export async function runPreflight(input: PreflightInput): Promise<PreflightReport> {
  const repoSlug = input.repoUrl ? parseGithubRepoUrl(input.repoUrl) ?? input.repoUrl.replace(/^\/+|\/+$/g, "") : undefined;
  let repo;
  if (repoSlug && repoSlug.includes("/")) {
    repo = await scanGithubRepo(repoSlug);
  }

  const auth = input.mcpUrl ? await probeAuth(input.mcpUrl) : {
    checks: {
      protectedResourceMetadata: false,
      authorizationServerMetadata: false,
      https: false,
      clientIdMetadataDocuments: false,
      dynamicClientRegistration: false,
      automatedClientOnboarding: false,
      oauth21Signals: false,
      pkceAdvertised: false,
    },
    scopeBreadth: "unknown" as const,
    notes: ["No MCP URL provided — auth checks require CLI or endpoint URL."],
  };

  let rawTools: { name: string; description?: string }[] = [];
  let tools = buildToolsReport([], "none");
  if (input.mcpUrl) {
    const live = await listMcpTools(input.mcpUrl);
    if (live.length) {
      rawTools = live;
      tools = buildToolsReport(live, "live");
    }
  }
  if (tools.toolCount === 0 && repoSlug?.includes("/")) {
    const guessed = await heuristicToolsFromRepo(repoSlug);
    if (guessed.length) {
      rawTools = guessed;
      tools = buildToolsReport(guessed, "repo-heuristic");
    }
  }

  const injection = scanToolText(rawTools);
  const directory = buildDirectoryChecklist(auth, tools, injection, repo);
  const score = computeScore(auth, tools, injection, directory, repo);
  const fixes = buildFixList(auth, tools, injection, directory);

  return {
    schemaVersion: "1.0",
    generatedAt: new Date(0).toISOString().replace(/\.000Z$/, "Z"), // deterministic timestamp for scoring runs
    input: { repoUrl: input.repoUrl, mcpUrl: input.mcpUrl },
    auth,
    tools,
    injection,
    directory,
    repo,
    score,
    fixes,
  };
}

/** Same as runPreflight but stamps real time (for CLI output). */
export async function runPreflightLive(input: PreflightInput): Promise<PreflightReport> {
  const report = await runPreflight(input);
  return { ...report, generatedAt: new Date().toISOString() };
}
