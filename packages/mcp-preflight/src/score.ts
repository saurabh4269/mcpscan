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
    authPts += auth.checks.protectedResourceMetadata ? 12 : 0;
    authPts += auth.checks.authorizationServerMetadata ? 8 : 0;
    authPts += auth.checks.clientIdMetadataDocuments ? 8 : 0;
    authPts += auth.checks.dynamicClientRegistration && !auth.checks.clientIdMetadataDocuments ? 5 : 0;
    authPts += auth.checks.oauth21Signals ? 4 : 0;
    authPts += auth.checks.pkceAdvertised ? 2 : 0;
    if (auth.scopeBreadth === "narrow") authPts += 3;
    else if (auth.scopeBreadth === "moderate") authPts += 2;
    else if (auth.scopeBreadth === "broad") authPts += 0;
    else authPts += 1;
  } else {
    authPts = 15;
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
  if (auth.mcpUrl && !auth.checks.protectedResourceMetadata) {
    fixes.push(
      "Publish OAuth 2.0 Protected Resource Metadata (RFC 9728) at /.well-known/oauth-protected-resource on the MCP server.",
    );
  }
  if (auth.mcpUrl && !auth.checks.authorizationServerMetadata) {
    fixes.push(
      "Ensure authorization-server metadata (RFC 8414 or OpenID Connect Discovery) is reachable from authorization_servers listed in protected-resource metadata.",
    );
  }
  if (auth.mcpUrl && !auth.checks.automatedClientOnboarding) {
    fixes.push(
      "Enable Client ID Metadata Documents (client_id_metadata_document_supported) or, for legacy hosts, Dynamic Client Registration (registration_endpoint).",
    );
  }
  if (auth.scopeBreadth === "broad") {
    fixes.push("Review OAuth scopes against MCP scope-minimization guidance; avoid overly broad scopes_supported.");
  }
  if (tools.summary.lethalTrifecta > 0) {
    fixes.push(
      "Review lethal-trifecta tools: separate read-private from network/exec paths; require human confirmation.",
    );
  }
  if (!injection.clean) {
    fixes.push("Rewrite tool descriptions to remove instruction-like or hidden text patterns.");
  }
  for (const item of directory.items.filter((i) => !i.passed && i.id !== "resource-indicator")) {
    fixes.push(`${item.title}: ${item.detail}`);
  }
  return [...new Set(fixes)].slice(0, 12);
}
