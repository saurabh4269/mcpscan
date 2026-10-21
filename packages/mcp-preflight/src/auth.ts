import type { AuthReport } from "./types.js";

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

export async function probeAuth(mcpUrl: string): Promise<AuthReport> {
  const base = authorizationBaseFromMcpUrl(mcpUrl);
  const notes: string[] = [];
  const https = new URL(mcpUrl).protocol === "https:";

  const prUrls = [
    `${base}/.well-known/oauth-protected-resource`,
    `${base}/.well-known/oauth-protected-resource${new URL(mcpUrl).pathname}`,
  ];
  let protectedResourceMetadata: Record<string, unknown> | null = null;
  for (const u of prUrls) {
    const r = await fetchJson(u);
    if (r.ok && r.json) {
      protectedResourceMetadata = r.json;
      break;
    }
  }

  const asUrls = [
    `${base}/.well-known/oauth-authorization-server`,
    `${base}/.well-known/oauth-authorization-server${new URL(mcpUrl).pathname}`,
  ];
  let authorizationServerMetadata: Record<string, unknown> | null = null;
  for (const u of asUrls) {
    const r = await fetchJson(u);
    if (r.ok && r.json) {
      authorizationServerMetadata = r.json;
      break;
    }
  }

  if (!authorizationServerMetadata && protectedResourceMetadata?.authorization_servers) {
    const servers = protectedResourceMetadata.authorization_servers as unknown[];
    const first = servers?.[0];
    if (typeof first === "string") {
      const r = await fetchJson(`${first.replace(/\/$/, "")}/.well-known/oauth-authorization-server`);
      if (r.ok && r.json) authorizationServerMetadata = r.json;
    }
  }

  const meta = authorizationServerMetadata ?? {};
  const registrationEndpoint = Boolean(
    meta.registration_endpoint || meta.registration_endpoint_uri,
  );
  const pkceMethods = (meta.code_challenge_methods_supported as string[] | undefined) ?? [];
  const pkceS256 = pkceMethods.map((m) => m.toUpperCase()).includes("S256");
  const metadataDiscovery = Boolean(authorizationServerMetadata);

  const grantTypes = (meta.grant_types_supported as string[] | undefined) ?? [];
  const oauth21Signals =
    grantTypes.includes("authorization_code") ||
    grantTypes.includes("urn:ietf:params:oauth:grant-type:device_code") ||
    Boolean(meta.token_endpoint);

  const scopesSupported = (meta.scopes_supported as string[] | undefined) ?? undefined;

  if (!https) notes.push("MCP authorization spec requires HTTPS for production endpoints.");
  if (!metadataDiscovery)
    notes.push(
      "No RFC 8414 authorization-server metadata found; clients fall back to default /authorize, /token, /register paths.",
    );
  if (!registrationEndpoint)
    notes.push(
      "No registration_endpoint in metadata — ChatGPT/Claude often fail with incompatible auth server (no dynamic client registration).",
    );
  if (!pkceS256) notes.push("PKCE S256 not advertised in code_challenge_methods_supported (required for public OAuth clients).");

  return {
    mcpUrl,
    authorizationBaseUrl: base,
    protectedResourceMetadata,
    authorizationServerMetadata,
    checks: {
      metadataDiscovery,
      https,
      registrationEndpoint,
      pkceS256,
      oauth21Signals,
    },
    scopesSupported,
    scopeBreadth: scopeBreadth(scopesSupported),
    notes,
  };
}
