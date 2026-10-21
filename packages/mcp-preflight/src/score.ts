import type { AuthReport, DirectoryReport, InjectionReport, RepoSignals, ScoreReport, ToolsReport } from "./types.js";
import { CODE_RISK_PENALTIES } from "./risk-patterns.js";

function grade(total: number): ScoreReport["grade"] {
  if (total >= 90) return "A";
  if (total >= 80) return "B";
  if (total >= 70) return "C";
  if (total >= 55) return "D";
  return "F";
}

export function computeScore(
  auth: AuthReport,
  tools: ToolsReport,
  injection: InjectionReport,
  directory: DirectoryReport,
  repo?: RepoSignals,
): ScoreReport {
  const max = 100;
  let authPts = 0;
  if (auth.mcpUrl) {
    authPts += auth.checks.https ? 5 : 0;
    authPts += auth.checks.metadataDiscovery ? 8 : 0;
    authPts += auth.checks.registrationEndpoint ? 10 : 0;
    authPts += auth.checks.pkceS256 ? 7 : 0;
    authPts += auth.checks.oauth21Signals ? 5 : 0;
    if (auth.scopeBreadth === "narrow") authPts += 5;
    else if (auth.scopeBreadth === "moderate") authPts += 3;
    else if (auth.scopeBreadth === "broad") authPts += 0;
    else authPts += 2;
  } else {
    authPts = 15; // repo-only partial credit
  }
  authPts = Math.min(40, authPts);

  let toolsPts = 25;
  toolsPts -= Math.min(10, tools.summary.exec * 3);
  toolsPts -= Math.min(8, tools.summary.write * 2);
  toolsPts -= Math.min(10, tools.summary.lethalTrifecta * 5);
  if (tools.toolCount === 0) toolsPts -= 8;
  toolsPts = Math.max(0, Math.min(25, toolsPts));

  let injectionPts = injection.clean ? 15 : Math.max(0, 15 - injection.findings.length * 3);

  const directoryPts = Math.round((directory.passed / directory.total) * 15);

  let supplyPts = 5;
  if (repo) {
    const pen = repo.riskyPatterns.reduce(
      (s, k) => s + ((CODE_RISK_PENALTIES as Record<string, number>)[k] ?? 0),
      0,
    );
    supplyPts = Math.max(0, 5 - Math.min(5, Math.floor(pen / 3)));
    if (repo.hasSecurityPolicy) supplyPts = Math.min(5, supplyPts + 1);
    if (repo.hasCi) supplyPts = Math.min(5, supplyPts + 1);
  }

  const breakdown = {
    auth: authPts,
    tools: toolsPts,
    injection: injectionPts,
    directory: directoryPts,
    supplyChain: Math.min(5, supplyPts),
  };
  const total = Math.min(
    max,
    breakdown.auth + breakdown.tools + breakdown.injection + breakdown.directory + breakdown.supplyChain,
  );

  return { total, max, breakdown, grade: grade(total) };
}

export function buildFixList(
  auth: AuthReport,
  tools: ToolsReport,
  injection: InjectionReport,
  directory: DirectoryReport,
): string[] {
  const fixes: string[] = [];
  if (auth.mcpUrl && !auth.checks.registrationEndpoint)
    fixes.push("Add OAuth Dynamic Client Registration (registration_endpoint) per RFC 7591 / MCP authorization spec.");
  if (auth.mcpUrl && !auth.checks.pkceS256)
    fixes.push("Advertise PKCE S256 in authorization-server metadata (code_challenge_methods_supported).");
  if (auth.mcpUrl && !auth.checks.metadataDiscovery)
    fixes.push("Publish RFC 8414 metadata at /.well-known/oauth-authorization-server on the MCP host.");
  if (auth.scopeBreadth === "broad")
    fixes.push("Narrow OAuth scopes to least privilege required for each tool.");
  if (tools.summary.lethalTrifecta > 0)
    fixes.push("Review lethal-trifecta tools: separate read-private from network/exec paths; require human confirmation.");
  if (!injection.clean)
    fixes.push("Rewrite tool descriptions to remove instruction-like or hidden text patterns.");
  for (const item of directory.items.filter((i) => !i.passed)) {
    fixes.push(`${item.title}: ${item.detail}`);
  }
  return [...new Set(fixes)].slice(0, 12);
}
