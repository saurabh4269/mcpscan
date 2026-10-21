import type { PreflightReport } from "./types.js";

export function formatReportMarkdown(r: PreflightReport): string {
  const lines: string[] = [];
  lines.push(`# MCP Security Preflight`);
  lines.push("");
  lines.push(`**Score:** ${r.score.total}/${r.score.max} (grade ${r.score.grade})`);
  if (r.input.repoUrl) lines.push(`**Repo:** ${r.input.repoUrl}`);
  if (r.input.mcpUrl) lines.push(`**MCP URL:** ${r.input.mcpUrl}`);
  lines.push(`**Tool fingerprint:** \`${r.tools.fingerprint}\``);
  lines.push("");

  lines.push("## Auth");
  for (const [k, v] of Object.entries(r.auth.checks)) {
    lines.push(`- ${k}: ${v ? "pass" : "fail"}`);
  }
  for (const n of r.auth.notes ?? []) lines.push(`- ${n}`);
  lines.push("");

  lines.push("## Tool risk map");
  lines.push(`Source: ${r.tools.source}, count: ${r.tools.toolCount}`);
  for (const t of r.tools.tools.slice(0, 30)) {
    lines.push(
      `- **${t.name}** [${t.capabilities.join(", ")}]${t.lethalTrifecta ? " ⚠ lethal-trifecta" : ""}`,
    );
  }
  if (r.tools.tools.length > 30) lines.push(`- … and ${r.tools.tools.length - 30} more`);
  lines.push("");

  lines.push("## Prompt-injection scan");
  if (r.injection.clean) lines.push("No suspicious patterns.");
  else {
    for (const f of r.injection.findings) {
      lines.push(`- ${f.tool} (${f.field}): ${f.pattern} — \`${f.excerpt}\``);
    }
  }
  lines.push("");

  lines.push("## Directory readiness");
  for (const item of r.directory.items) {
    lines.push(`- [${item.passed ? "x" : " "}] ${item.title}`);
  }
  lines.push("");

  lines.push("## Fixes");
  for (const fix of r.fixes) lines.push(`1. ${fix}`);
  return lines.join("\n");
}
