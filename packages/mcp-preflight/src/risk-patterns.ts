import cfg from "../../../shared/risk_patterns.json" with { type: "json" };
import type { ToolCapability } from "./types.js";

export const CODE_RISK_PATTERNS = cfg.patterns;
export const CODE_RISK_PENALTIES = cfg.penalties;

const READ_RX =
  /\b(get|list|fetch|read|search|query|find|describe|lookup|view|show|retrieve|download)\b/i;
const WRITE_RX =
  /\b(create|update|delete|remove|write|post|put|patch|send|publish|upload|insert|set|modify|edit)\b/i;
const EXEC_RX =
  /\b(exec|execute|run|shell|command|spawn|eval|invoke|script|terminal|bash|powershell)\b/i;
const NET_RX =
  /\b(http|https|fetch|request|url|webhook|api|curl|proxy|egress|download|upload)\b/i;
const PRIVATE_RX =
  /\b(password|secret|token|credential|private|ssn|api[_-]?key|auth|session|cookie|pii|personal)\b/i;
const UNTRUSTED_RX =
  /\b(user|input|prompt|message|query|parameter|arg|payload|content|text|html|markdown|url)\b/i;

export function classifyTool(name: string, description: string): {
  capabilities: ToolCapability[];
  reasons: string[];
  lethalTrifecta: boolean;
} {
  const blob = `${name} ${description}`;
  const capabilities: ToolCapability[] = [];
  const reasons: string[] = [];

  if (READ_RX.test(blob)) {
    capabilities.push("read");
    reasons.push("name/description suggests read access");
  }
  if (WRITE_RX.test(blob)) {
    capabilities.push("write");
    reasons.push("name/description suggests write/mutate");
  }
  if (EXEC_RX.test(blob)) {
    capabilities.push("exec");
    reasons.push("name/description suggests code/shell execution");
  }
  if (NET_RX.test(blob)) {
    capabilities.push("network");
    reasons.push("name/description suggests network egress");
  }
  if (!capabilities.length) {
    capabilities.push("read");
    reasons.push("default: treat unknown tools as read-capable until reviewed");
  }

  const lethalTrifecta =
    (PRIVATE_RX.test(blob) || capabilities.includes("read")) &&
    UNTRUSTED_RX.test(blob) &&
    (capabilities.includes("network") || capabilities.includes("exec"));

  return { capabilities: [...new Set(capabilities)], reasons, lethalTrifecta };
}

export function riskyPatternsInText(text: string): string[] {
  const found: string[] = [];
  for (const [k, pattern] of Object.entries(CODE_RISK_PATTERNS)) {
    if (new RegExp(pattern, "i").test(text)) found.push(k);
  }
  return found;
}
