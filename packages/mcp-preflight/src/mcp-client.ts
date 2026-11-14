export interface McpTool {
  name: string;
  description?: string;
}

/** Minimal streamable-HTTP MCP tools/list (no SDK dependency). */
export async function listMcpTools(mcpUrl: string, timeoutMs = 20000): Promise<McpTool[]> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  const sessionId = crypto.randomUUID();

  const headers: Record<string, string> = {
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2024-11-05",
    "MCP-Session-Id": sessionId,
    "User-Agent": "mcp-preflight/0.1",
  };

  const initBody = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "mcp-preflight", version: "0.1.0" },
    },
  };

  try {
    const initRes = await fetch(mcpUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(initBody),
      signal: ctrl.signal,
    });
    if (!initRes.ok) return [];

    await fetch(mcpUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      signal: ctrl.signal,
    });

    const listRes = await fetch(mcpUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
      signal: ctrl.signal,
    });
    if (!listRes.ok) return [];

    const text = await listRes.text();
    const jsonLine = text
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l.startsWith("{"));
    if (!jsonLine) return [];
    const parsed = JSON.parse(jsonLine) as {
      result?: { tools?: { name: string; description?: string }[] };
    };
    return (parsed.result?.tools ?? []).map((tool) => ({
      name: tool.name,
      description: tool.description,
    }));
  } catch {
    return [];
  } finally {
    clearTimeout(t);
  }
}
