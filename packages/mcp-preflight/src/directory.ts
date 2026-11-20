import type { AuthReport, DirectoryItem, DirectoryReport, InjectionReport, RepoSignals, ToolsReport } from "./types.js";
import { MCP_AUTH_SPEC_URL } from "./auth.js";

const CITATIONS = {
  mcpAuth: MCP_AUTH_SPEC_URL,
  mcpClientRegistration:
    "https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration",
  rfc9728: "https://datatracker.ietf.org/doc/html/rfc9728",
  rfc8414: "https://datatracker.ietf.org/doc/html/rfc8414",
  rfc8707: "https://datatracker.ietf.org/doc/html/rfc8707",
  rfc7591: "https://datatracker.ietf.org/doc/html/rfc7591",
  anthropicMcp:
    "https://docs.anthropic.com/en/docs/agents-and-tools/mcp-connector",
  openaiMcp: "https://platform.openai.com/docs/mcp",
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
      title: "Remote MCP endpoint uses HTTPS",
      passed: auth.mcpUrl ? auth.checks.https : false,
      detail: auth.mcpUrl
        ? auth.checks.https
          ? "MCP URL uses TLS."
          : "Use HTTPS for production OAuth and MCP HTTP transports."
        : "Repo-only scan: verify deployed MCP URL is HTTPS before submission.",
      citation: CITATIONS.mcpAuth,
    },
    {
      id: "protected-resource-metadata",
      title: "OAuth protected-resource metadata (RFC 9728)",
      passed: Boolean(auth.mcpUrl && auth.checks.protectedResourceMetadata),
      detail: auth.mcpUrl
        ? auth.checks.protectedResourceMetadata
          ? "Protected-resource metadata document discovered (authorization-server discovery entry point)."
          : "Missing RFC 9728 metadata — required on MCP servers when OAuth is supported."
        : "Not tested in browser — run: npx mcp-preflight --mcp <url>",
      citation: CITATIONS.rfc9728,
    },
    {
      id: "authorization-server-metadata",
      title: "Authorization-server metadata discoverable",
      passed: Boolean(auth.mcpUrl && auth.checks.authorizationServerMetadata),
      detail: auth.mcpUrl
        ? auth.checks.authorizationServerMetadata
          ? "RFC 8414 or OpenID Connect Discovery metadata fetched from linked authorization server."
          : "Could not fetch authorization-server metadata after protected-resource discovery."
        : "Not tested in browser — run: npx mcp-preflight --mcp <url>",
      citation: CITATIONS.rfc8414,
    },
    {
      id: "client-onboarding",
      title: "Automated client onboarding (CIMD or DCR)",
      passed: Boolean(auth.mcpUrl && auth.checks.automatedClientOnboarding),
      detail: auth.mcpUrl
        ? auth.checks.clientIdMetadataDocuments
          ? "Client ID Metadata Documents supported (preferred)."
          : auth.checks.dynamicClientRegistration
            ? "Dynamic Client Registration available (optional legacy fallback)."
            : "Only pre-registration may be available — valid per MCP but some assistant hosts expect CIMD or DCR."
        : "Not tested in browser — run: npx mcp-preflight --mcp <url>",
      citation: CITATIONS.mcpClientRegistration,
    },
    {
      id: "resource-indicator",
      title: "Resource identifier in metadata (informational)",
      passed: true,
      detail: auth.mcpUrl
        ? auth.resourceIndicator
          ? `resource field: ${auth.resourceIndicator} (RFC 8707 audience binding).`
          : auth.checks.protectedResourceMetadata
            ? "Protected-resource metadata has no resource field — clients still send the resource parameter per MCP."
            : "No protected-resource metadata to inspect."
        : "Not tested in browser.",
      citation: CITATIONS.rfc8707,
    },
    {
      id: "scope-breadth",
      title: "Token scopes appear least-privilege (heuristic)",
      passed: auth.scopeBreadth !== "broad",
      detail: `Scope breadth heuristic: ${auth.scopeBreadth}${
        auth.scopesSupported?.length ? ` (${auth.scopesSupported.join(", ")})` : ""
      }. MCP scope challenges may differ from scopes_supported.`,
      citation: CITATIONS.mcpAuth,
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
