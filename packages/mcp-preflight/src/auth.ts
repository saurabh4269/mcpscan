import type { AuthReport } from "./types.js";

/** MCP draft authorization spec (current revision). */
export const MCP_AUTH_SPEC_URL =
  "https://modelcontextprotocol.io/specification/draft/basic/authorization";

const MCP_PROTOCOL_HEADER = "2024-11-05";

export function authorizationBaseFromMcpUrl(mcpUrl: string): string {
  const u = new URL(mcpUrl);
  return `${u.protocol}//${u.host}`;
}

async function fetchJson(
  url: string,
  timeoutMs = 15000,
): Promise<{ ok: boolean; status: number; json?: Record<string, unknown> }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: {
        Accept: "application/json",
        "MCP-Protocol-Version": MCP_PROTOCOL_HEADER,
        "User-Agent": "mcp-preflight/0.1",
      },
      redirect: "follow",
    });
    if (!res.ok) return { ok: false, status: res.status };
    const json = (await res.json()) as Record<string, unknown>;
    return { ok: true, status: res.status, json };
  } catch {
    return { ok: false, status: 0 };
  } finally {
    clearTimeout(t);
  }
}

function scopeBreadth(scopes: string[] | undefined): AuthReport["scopeBreadth"] {
  if (!scopes?.length) return "none";
  const joined = scopes.join(" ").toLowerCase();
  if (/\b(admin|root|all|full|write|delete)\b/.test(joined) || scopes.length > 8) return "broad";
  if (scopes.length > 3) return "moderate";
  return "narrow";
}

async function discoverAuthorizationServerMetadata(
  asBase: string,
): Promise<Record<string, unknown> | null> {
  const base = asBase.replace(/\/$/, "");
  const candidates = [
    `${base}/.well-known/oauth-authorization-server`,
    `${base}/.well-known/openid-configuration`,
  ];
  for (const u of candidates) {
    const r = await fetchJson(u);
    if (r.ok && r.json) return r.json;
  }
  return null;
}

export async function probeAuth(mcpUrl: string): Promise<AuthReport> {
  const base = authorizationBaseFromMcpUrl(mcpUrl);
  const notes: string[] = [];
  const https = new URL(mcpUrl).protocol === "https:";

  const resourceParam = encodeURIComponent(mcpUrl);
  const prUrls = [
    `${base}/.well-known/oauth-protected-resource`,
    `${base}/.well-known/oauth-protected-resource${new URL(mcpUrl).pathname}`,
    `${base}/.well-known/oauth-protected-resource?resource=${resourceParam}`,
  ];
  let protectedResourceMetadata: Record<string, unknown> | null = null;
  for (const u of prUrls) {
    const r = await fetchJson(u);
    if (r.ok && r.json) {
      protectedResourceMetadata = r.json;
      break;
    }
  }

  let authorizationServerMetadata: Record<string, unknown> | null = null;
  if (protectedResourceMetadata?.authorization_servers) {
    const servers = protectedResourceMetadata.authorization_servers as unknown[];
    for (const entry of servers) {
      if (typeof entry !== "string") continue;
      authorizationServerMetadata = await discoverAuthorizationServerMetadata(entry);
      if (authorizationServerMetadata) break;
    }
  }

  if (!authorizationServerMetadata) {
    const legacyAsUrls = [
      `${base}/.well-known/oauth-authorization-server`,
      `${base}/.well-known/oauth-authorization-server${new URL(mcpUrl).pathname}`,
    ];
    for (const u of legacyAsUrls) {
      const r = await fetchJson(u);
      if (r.ok && r.json) {
        authorizationServerMetadata = r.json;
        notes.push(
          "Authorization-server metadata served at MCP host (legacy path). Current MCP spec expects RFC 9728 protected-resource metadata for discovery.",
        );
        break;
      }
    }
  }

  const meta = authorizationServerMetadata ?? {};
  const protectedResourceMetadataPresent = Boolean(protectedResourceMetadata);
  const authorizationServerMetadataPresent = Boolean(authorizationServerMetadata);

  const clientIdMetadataDocuments = meta.client_id_metadata_document_supported === true;
  const dynamicClientRegistration = Boolean(
    meta.registration_endpoint || meta.registration_endpoint_uri,
  );
  const automatedClientOnboarding = clientIdMetadataDocuments || dynamicClientRegistration;

  const pkceMethods = (meta.code_challenge_methods_supported as string[] | undefined) ?? [];
  const pkceAdvertised = pkceMethods.map((m) => m.toUpperCase()).includes("S256");

  const grantTypes = (meta.grant_types_supported as string[] | undefined) ?? [];
  const oauth21Signals =
    grantTypes.includes("authorization_code") ||
    grantTypes.includes("urn:ietf:params:oauth:grant-type:device_code") ||
    Boolean(meta.token_endpoint);

  const prScopes = protectedResourceMetadata?.scopes_supported as string[] | undefined;
  const asScopes = meta.scopes_supported as string[] | undefined;
  const scopesSupported = prScopes?.length ? prScopes : asScopes;

  const resourceIndicator =
    typeof protectedResourceMetadata?.resource === "string"
      ? protectedResourceMetadata.resource
      : undefined;

  if (!https) {
    notes.push("OAuth endpoints should use HTTPS (MCP authorization security requirements).");
  }
  if (!protectedResourceMetadataPresent) {
    notes.push(
      "No RFC 9728 protected-resource metadata found. When this server uses OAuth, MCP requires protected-resource metadata for authorization-server discovery.",
    );
  } else if (resourceIndicator) {
    notes.push(`Protected-resource metadata resource identifier: ${resourceIndicator} (RFC 8707 / RFC 9728).`);
  }
  if (!authorizationServerMetadataPresent && protectedResourceMetadataPresent) {
    notes.push(
      "Protected-resource metadata found but authorization-server metadata could not be fetched (RFC 8414 or OpenID Connect Discovery).",
    );
  }
  if (authorizationServerMetadataPresent && !automatedClientOnboarding) {
    notes.push(
      "No Client ID Metadata Documents support and no registration_endpoint — clients may need pre-registered OAuth credentials (allowed by MCP client registration).",
    );
  }
  if (clientIdMetadataDocuments) {
    notes.push(
      "Authorization server supports Client ID Metadata Documents (preferred MCP client registration path).",
    );
  } else if (dynamicClientRegistration) {
    notes.push(
      "Authorization server exposes Dynamic Client Registration (RFC 7591) — optional in current MCP spec; Client ID Metadata Documents are preferred for new implementations.",
    );
  }
  if (!pkceAdvertised) {
    notes.push(
      "PKCE S256 not listed in code_challenge_methods_supported (informational). OAuth 2.1 still requires MCP clients to use PKCE; many hosts work without advertising S256.",
    );
  }

  return {
    mcpUrl,
    authorizationBaseUrl: base,
    protectedResourceMetadata,
    authorizationServerMetadata,
    resourceIndicator,
    checks: {
      protectedResourceMetadata: protectedResourceMetadataPresent,
      authorizationServerMetadata: authorizationServerMetadataPresent,
      https,
      clientIdMetadataDocuments,
      dynamicClientRegistration,
      automatedClientOnboarding,
      oauth21Signals,
      pkceAdvertised,
    },
    scopesSupported,
    scopeBreadth: scopeBreadth(scopesSupported),
    notes,
  };
}
