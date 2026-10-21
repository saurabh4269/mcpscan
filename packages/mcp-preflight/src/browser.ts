import { buildDirectoryChecklist } from "./directory.js";
import { scanToolText } from "./injection.js";
import { heuristicToolsFromRepo, parseGithubRepoUrl, scanGithubRepo } from "./repo.js";
import { buildFixList, computeScore } from "./score.js";
import { buildToolsReport } from "./tools-report.js";
import type { PreflightReport } from "./types.js";

/** Browser-only preflight (GitHub API). Live MCP/auth probing requires the CLI. */
export async function runBrowserPreflight(repoUrl: string): Promise<PreflightReport> {
  const slug = parseGithubRepoUrl(repoUrl);
  if (!slug) throw new Error("Enter a valid GitHub repository URL");
  const repo = await scanGithubRepo(slug);
  const rawTools = await heuristicToolsFromRepo(slug);
  const tools = buildToolsReport(rawTools, rawTools.length ? "repo-heuristic" : "none");
  const injection = scanToolText(rawTools);
  const auth = {
    checks: {
      metadataDiscovery: false,
      https: false,
      registrationEndpoint: false,
      pkceS256: false,
      oauth21Signals: false,
    },
    scopeBreadth: "unknown" as const,
    notes: ["Browser scan is repo-only. Run npx mcp-preflight --mcp <url> for OAuth metadata and live tools."],
  };
  const directory = buildDirectoryChecklist(auth, tools, injection, repo);
  const score = computeScore(auth, tools, injection, directory, repo);
  const fixes = buildFixList(auth, tools, injection, directory);
  return {
    schemaVersion: "1.0",
    generatedAt: new Date().toISOString(),
    input: { repoUrl },
    auth,
    tools,
    injection,
    directory,
    repo,
    score,
    fixes,
  };
}

function el(id: string): HTMLElement {
  const n = document.getElementById(id);
  if (!n) throw new Error(`missing #${id}`);
  return n;
}

function render(report: PreflightReport): void {
  el("score").textContent = `${report.score.total}/${report.score.max} (${report.score.grade})`;
  el("fingerprint").textContent = report.tools.fingerprint;
  el("tools").innerHTML = report.tools.tools
    .slice(0, 40)
    .map(
      (t) =>
        `<tr><td>${t.name}</td><td>${t.capabilities.join(", ")}</td><td>${t.lethalTrifecta ? "yes" : ""}</td></tr>`,
    )
    .join("");
  el("directory").innerHTML = report.directory.items
    .map((i) => `<li class="${i.passed ? "ok" : "bad"}">${i.title}</li>`)
    .join("");
  el("fixes").innerHTML = report.fixes.map((f) => `<li>${f}</li>`).join("");
  el("raw").textContent = JSON.stringify(report, null, 2);
}

export function mountPreflightUi(): void {
  const form = el("preflight-form") as HTMLFormElement;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const repo = (el("repo-input") as HTMLInputElement).value.trim();
    el("status").textContent = "Scanning…";
    try {
      const report = await runBrowserPreflight(repo);
      render(report);
      el("status").textContent = "Done";
    } catch (err) {
      el("status").textContent = String(err);
    }
  });
}

mountPreflightUi();
