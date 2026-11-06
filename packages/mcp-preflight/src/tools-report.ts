import { classifyTool } from "./risk-patterns.js";
import { toolListFingerprint } from "./fingerprint.js";
import type { ToolRiskRow, ToolsReport } from "./types.js";

export function buildToolsReport(
  tools: { name: string; description?: string }[],
  source: ToolsReport["source"],
): ToolsReport {
  const rows: ToolRiskRow[] = tools.map((t) => {
    const { capabilities, reasons, lethalTrifecta } = classifyTool(t.name, t.description ?? "");
    return { name: t.name, capabilities, lethalTrifecta, reasons };
  });
  rows.sort((a, b) => a.name.localeCompare(b.name));

  const summary = { read: 0, write: 0, exec: 0, network: 0, lethalTrifecta: 0 };
  for (const r of rows) {
    if (r.capabilities.includes("read")) summary.read++;
    if (r.capabilities.includes("write")) summary.write++;
    if (r.capabilities.includes("exec")) summary.exec++;
    if (r.capabilities.includes("network")) summary.network++;
    if (r.lethalTrifecta) summary.lethalTrifecta++;
  }

  return {
    source,
    fingerprint: toolListFingerprint(tools),
    toolCount: tools.length,
    tools: rows,
    summary,
  };
}
