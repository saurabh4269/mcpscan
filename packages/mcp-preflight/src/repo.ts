import { riskyPatternsInText } from "./risk-patterns.js";
import type { RepoSignals } from "./types.js";

export function parseGithubRepoUrl(input: string): string | null {
  const m = input.match(/github\.com\/([\w.-]+\/[\w.-]+)/i);
  if (!m) return null;
  return m[1].replace(/\.git$/, "").replace(/\/$/, "");
}

async function ghGet(path: string): Promise<unknown> {
  const res = await fetch(`https://api.github.com${path}`, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "mcp-preflight",
    },
  });
  if (!res.ok) return null;
  return res.json();
}

async function rawFile(fullName: string, branch: string, path: string): Promise<string> {
  const res = await fetch(
    `https://raw.githubusercontent.com/${fullName}/${branch}/${path}`,
    { headers: { "User-Agent": "mcp-preflight" } },
  );
  if (!res.ok) return "";
  return res.text();
}

export async function scanGithubRepo(fullName: string): Promise<RepoSignals> {
  const repo = (await ghGet(`/repos/${fullName}`)) as {
    default_branch?: string;
    license?: { spdx_id?: string };
    description?: string;
  } | null;
  const branch = repo?.default_branch ?? "main";
  const tree = (await ghGet(`/repos/${fullName}/git/trees/${branch}?recursive=1`)) as {
    tree?: { path: string; type: string }[];
  } | null;
  const files = (tree?.tree ?? []).filter((t) => t.type === "blob").map((t) => t.path);
  const src = files
    .filter((f) => /\.(ts|js|mjs|py|go|rs)$/i.test(f) && !/test|node_modules|dist\/|example/i.test(f))
    .sort((a, b) => a.split("/").length - b.split("/").length || a.length - b.length)
    .slice(0, 6);

  let blob = "";
  for (const f of src) blob += (await rawFile(fullName, branch, f)).slice(0, 200_000);

  const risky = riskyPatternsInText(blob);
  return {
    fullName,
    defaultBranch: branch,
    license: repo?.license?.spdx_id ?? null,
    hasReadme: files.some((f) => /^readme/i.test(f)),
    hasSecurityPolicy: files.some((f) => /security\.md/i.test(f)),
    hasCi: files.some((f) => f.startsWith(".github/workflows/")),
    riskyPatterns: risky,
    description: repo?.description,
  };
}

/** Heuristic tools inferred from README / package metadata when live MCP is unavailable. */
export async function heuristicToolsFromRepo(fullName: string): Promise<{ name: string; description?: string }[]> {
  const repo = (await ghGet(`/repos/${fullName}`)) as { default_branch?: string } | null;
  const branch = repo?.default_branch ?? "main";
  const readme =
    (await rawFile(fullName, branch, "README.md")) ||
    (await rawFile(fullName, branch, "readme.md"));
  const tools: { name: string; description?: string }[] = [];
  const toolHeaders = readme.match(/^#{1,3}\s+tools?\b/im);
  if (toolHeaders) {
    const section = readme.split(/^#{1,3}\s+tools?\b/im)[1] ?? "";
    for (const line of section.split("\n").slice(0, 80)) {
      const bullet = line.match(/^\s*[-*]\s*`([^`]+)`\s*[-–:]?\s*(.*)$/);
      if (bullet) tools.push({ name: bullet[1], description: bullet[2] });
    }
  }
  if (!tools.length) {
    for (const m of readme.matchAll(/`([a-z][a-z0-9_-]{2,})`/gi)) {
      if (tools.length >= 12) break;
      if (!tools.some((t) => t.name === m[1])) tools.push({ name: m[1], description: "mentioned in README" });
    }
  }
  return tools.slice(0, 40);
}
