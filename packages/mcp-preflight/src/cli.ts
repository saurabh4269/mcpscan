#!/usr/bin/env node
import { formatReportMarkdown } from "./format.js";
import { runPreflightLive } from "./run.js";

function usage(): void {
  console.error(`Usage: mcp-preflight [--repo <github-url>] [--mcp <mcp-endpoint-url>] [--json]

Examples:
  npx mcp-preflight --mcp https://mcp.context7.com/mcp
  npx mcp-preflight --repo https://github.com/modelcontextprotocol/servers
  npx mcp-preflight --repo owner/repo --mcp https://example.com/mcp`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let repoUrl: string | undefined;
  let mcpUrl: string | undefined;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--repo") repoUrl = args[++i];
    else if (a === "--mcp") mcpUrl = args[++i];
    else if (a === "--json") json = true;
    else if (a === "-h" || a === "--help") {
      usage();
      process.exit(0);
    } else if (!a.startsWith("-")) {
      if (a.includes("github.com") || a.includes("/")) repoUrl = a;
      else if (a.startsWith("http")) mcpUrl = a;
    }
  }

  if (!repoUrl && !mcpUrl) {
    usage();
    process.exit(1);
  }

  const report = await runPreflightLive({ repoUrl, mcpUrl });
  if (json) console.log(JSON.stringify(report, null, 2));
  else console.log(formatReportMarkdown(report));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
