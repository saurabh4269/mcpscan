import type { InjectionFinding, InjectionReport } from "./types.js";

const PATTERNS: { id: string; re: RegExp }[] = [
  { id: "ignore-instructions", re: /\bignore (all |previous |prior )?(instructions|rules|guidelines)\b/i },
  { id: "system-prompt", re: /\b(system prompt|developer message|hidden instruction)\b/i },
  { id: "role-override", re: /\byou are now\b|\bact as\b.*\bwithout\b/i },
  { id: "exfiltration", re: /\b(send|post|transmit).{0,40}\b(secret|token|password|api[_-]?key)\b/i },
  { id: "markdown-hide", re: /<!--[\s\S]*?-->/ },
  { id: "zero-width", re: /[\u200B-\u200D\uFEFF]/ },
  { id: "base64-chunk", re: /\b[A-Za-z0-9+/]{80,}={0,2}\b/ },
];

export function scanToolText(
  tools: { name: string; description?: string }[],
): InjectionReport {
  const findings: InjectionFinding[] = [];

  for (const tool of tools) {
    for (const field of ["name", "description"] as const) {
      const text = field === "name" ? tool.name : tool.description ?? "";
      if (!text) continue;
      for (const { id, re } of PATTERNS) {
        const m = re.exec(text);
        if (m) {
          const start = Math.max(0, m.index - 20);
          findings.push({
            tool: tool.name,
            field,
            pattern: id,
            excerpt: text.slice(start, start + 80),
          });
        }
      }
    }
  }

  findings.sort((a, b) =>
    `${a.tool}:${a.field}:${a.pattern}`.localeCompare(`${b.tool}:${b.field}:${b.pattern}`),
  );

  return { findings, clean: findings.length === 0 };
}
