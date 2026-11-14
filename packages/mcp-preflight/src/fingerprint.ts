import { sha256Hex } from "./sha256.js";

export interface ToolFingerprintInput {
  name: string;
  description?: string;
}

/** Stable SHA-256 over sorted tool name + normalized description. */
export function toolListFingerprint(tools: ToolFingerprintInput[]): string {
  const normalized = tools
    .map((t) => ({
      name: t.name.trim(),
      description: (t.description ?? "").replace(/\s+/g, " ").trim().toLowerCase(),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  const payload = JSON.stringify(normalized);
  return sha256Hex(payload);
}
