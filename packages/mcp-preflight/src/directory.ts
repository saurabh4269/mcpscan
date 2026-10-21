import type { AuthReport, DirectoryItem, DirectoryReport, InjectionReport, RepoSignals, ToolsReport } from "./types.js";

const CITATIONS = {
  mcpAuth:
    "https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization",
  rfc8414: "https://datatracker.ietf.org/doc/html/rfc8414",
  rfc7591: "https://datatracker.ietf.org/doc/html/rfc7591",
  anthropicMcp:
    "https://docs.anthropic.com/en/docs/agents-and-tools/mcp-connector",
  openaiMcp: "https://platform.openai.com/docs/mcp",
  openaiAuth:
    "https://platform.openai.com/docs/mcp#authentication",
};

export function buildDirectoryChecklist(
  auth: AuthReport,
  tools: ToolsReport,
  injection: InjectionReport,
  repo?: RepoSignals,
): DirectoryReport {
  const items: DirectoryItem[] = [
    {
      id: "https-transport",
      title: "Remote server uses HTTPS",
      passed: auth.mcpUrl ? auth.checks.https : false,
      detail: auth.mcpUrl
        ? auth.checks.https
          ? "MCP URL uses TLS."
          : "HTTP endpoints are rejected for production connector review."
        : "Repo-only scan: verify deployed MCP URL is HTTPS before submission.",
      citation: CITATIONS.mcpAuth,
    },
    {
      id: "oauth-metadata",
      title: "OAuth authorization-server metadata (RFC 8414)",
      passed: Boolean(auth.mcpUrl && auth.checks.metadataDiscovery),
      detail: auth.mcpUrl
        ? auth.checks.metadataDiscovery
          ? "Metadata document discovered."
          : "Missing /.well-known/oauth-authorization-server — clients must guess endpoints."
        : "Not tested in browser — run: npx mcp-preflight --mcp <url>",
      citation: CITATIONS.rfc8414,
    },
    {
      id: "dynamic-registration",
      title: "Dynamic client registration (RFC 7591)",
      passed: Boolean(auth.mcpUrl && auth.checks.registrationEndpoint),
      detail: auth.mcpUrl
        ? auth.checks.registrationEndpoint
          ? "registration_endpoint present."
          : "No DCR — common cause of “Incompatible auth server: does not support dynamic client registration”."
        : "Not tested in browser — run: npx mcp-preflight --mcp <url>",
      citation: CITATIONS.rfc7591,
    },
    {
      id: "pkce",
      title: "PKCE S256 for public clients",
      passed: Boolean(auth.mcpUrl && auth.checks.pkceS256),
      detail: auth.mcpUrl
        ? auth.checks.pkceS256
          ? "S256 listed in code_challenge_methods_supported."
          : "PKCE S256 not advertised."
        : "Not tested in browser — run: npx mcp-preflight --mcp <url>",
      citation: CITATIONS.mcpAuth,
    },
    {
      id: "scope-breadth",
      title: "Token scopes are not overly broad",
      passed: auth.scopeBreadth !== "broad",
      detail: `Scope breadth: ${auth.scopeBreadth}${
        auth.scopesSupported?.length ? ` (${auth.scopesSupported.join(", ")})` : ""
      }.`,
      citation: CITATIONS.openaiMcp,
    },
    {
      id: "tool-surface",
      title: "Tool surface documented and bounded",
      passed: tools.toolCount > 0 && tools.toolCount <= 50,
      detail:
        tools.toolCount === 0
          ? "No tools discovered — directories expect a clear tool list."
          : `${tools.toolCount} tools (fingerprint ${tools.fingerprint.slice(0, 12)}…).`,
      citation: CITATIONS.anthropicMcp,
    },
    {
      id: "lethal-trifecta",
      title: "No lethal-trifecta tool combos flagged",
      passed: tools.summary.lethalTrifecta === 0,
      detail:
        tools.summary.lethalTrifecta === 0
          ? "No private-data + untrusted-input + egress/exec combo detected in heuristics."
          : `${tools.summary.lethalTrifecta} tool(s) match lethal-trifecta pattern — document mitigations.`,
      citation: CITATIONS.openaiMcp,
    },
    {
      id: "prompt-injection",
      title: "Tool names/descriptions free of injection patterns",
      passed: injection.clean,
      detail: injection.clean
        ? "No suspicious instruction-like patterns in tool metadata."
        : `${injection.findings.length} pattern(s) matched — review before directory submission.`,
      citation: CITATIONS.openaiMcp,
    },
    {
      id: "readme",
      title: "README documents purpose and setup",
      passed: repo?.hasReadme ?? true,
      detail: repo?.hasReadme ? "README present." : "Add README with install, auth, and tool overview.",
      citation: CITATIONS.openaiMcp,
    },
    {
      id: "license",
      title: "SPDX license declared",
      passed: Boolean(repo?.license && repo.license !== "NOASSERTION"),
      detail: repo?.license ? `License: ${repo.license}` : "Declare a license on GitHub for directory review.",
      citation: CITATIONS.openaiMcp,
    },
    {
      id: "security-policy",
      title: "SECURITY.md or security contact",
      passed: repo?.hasSecurityPolicy ?? false,
      detail: repo?.hasSecurityPolicy
        ? "SECURITY.md found."
        : "Recommended: SECURITY.md with disclosure process (OpenAI risk guidance).",
      citation: CITATIONS.openaiMcp,
    },
    {
      id: "ci",
      title: "CI workflow present",
      passed: repo?.hasCi ?? false,
      detail: repo?.hasCi ? "GitHub Actions workflow detected." : "CI not detected — not always required but improves trust.",
      citation: CITATIONS.openaiMcp,
    },
  ];

  const passed = items.filter((i) => i.passed).length;
  return { items, passed, total: items.length };
}
