export type ToolCapability = "read" | "write" | "exec" | "network";

export interface AuthReport {
  mcpUrl?: string;
  authorizationBaseUrl?: string;
  protectedResourceMetadata?: Record<string, unknown> | null;
  authorizationServerMetadata?: Record<string, unknown> | null;
  /** Canonical resource URI from RFC 9728 metadata when present. */
  resourceIndicator?: string;
  checks: {
    /** RFC 9728 — required on MCP servers when OAuth is used. */
    protectedResourceMetadata: boolean;
    /** RFC 8414 or OpenID Connect Discovery on the authorization server. */
    authorizationServerMetadata: boolean;
    https: boolean;
    /** client_id_metadata_document_supported (preferred registration). */
    clientIdMetadataDocuments: boolean;
    /** registration_endpoint (optional / legacy fallback). */
    dynamicClientRegistration: boolean;
    /** CIMD or DCR — either satisfies automated onboarding. */
    automatedClientOnboarding: boolean;
    oauth21Signals: boolean;
    /** Informational only — not a spec compliance requirement for servers. */
    pkceAdvertised: boolean;
  };
  scopesSupported?: string[];
  scopeBreadth: "none" | "narrow" | "moderate" | "broad" | "unknown";
  notes: string[];
}

export interface ToolRiskRow {
  name: string;
  capabilities: ToolCapability[];
  lethalTrifecta: boolean;
  reasons: string[];
}

export interface ToolsReport {
  source: "live" | "repo-heuristic" | "none";
  fingerprint: string;
  toolCount: number;
  tools: ToolRiskRow[];
  summary: { read: number; write: number; exec: number; network: number; lethalTrifecta: number };
}

export interface InjectionFinding {
  tool: string;
  field: "name" | "description";
  pattern: string;
  excerpt: string;
}

export interface InjectionReport {
  findings: InjectionFinding[];
  clean: boolean;
}

export interface DirectoryItem {
  id: string;
  title: string;
  passed: boolean;
  detail: string;
  citation: string;
}

export interface DirectoryReport {
  items: DirectoryItem[];
  passed: number;
  total: number;
}

export interface ScoreBreakdown {
  auth: number;
  tools: number;
  injection: number;
  directory: number;
  supplyChain: number;
}

export interface ScoreReport {
  total: number;
  max: number;
  breakdown: ScoreBreakdown;
  grade: "A" | "B" | "C" | "D" | "F";
}

export interface RepoSignals {
  fullName: string;
  defaultBranch: string;
  license?: string | null;
  hasReadme: boolean;
  hasSecurityPolicy: boolean;
  hasCi: boolean;
  riskyPatterns: string[];
  description?: string;
}

export interface PreflightReport {
  schemaVersion: "1.0";
  generatedAt: string;
  input: { repoUrl?: string; mcpUrl?: string };
  auth: AuthReport;
  tools: ToolsReport;
  injection: InjectionReport;
  directory: DirectoryReport;
  repo?: RepoSignals;
  score: ScoreReport;
  fixes: string[];
}
