import { describe, expect, it } from "vitest";
import { runPreflight } from "../src/run.js";
import { probeAuth } from "../src/auth.js";
import { scanGithubRepo } from "../src/repo.js";

const SERVERS = [
  {
    name: "context7-remote",
    mcpUrl: "https://mcp.context7.com/mcp",
    repoUrl: "https://github.com/upstash/context7",
  },
  {
    name: "chrome-devtools-mcp",
    repoUrl: "https://github.com/ChromeDevTools/chrome-devtools-mcp",
  },
  {
    name: "playwright-mcp",
    repoUrl: "https://github.com/microsoft/playwright-mcp",
  },
];

describe("integration: MCPScan dataset servers", () => {
  for (const s of SERVERS) {
    it(`preflight ${s.name}`, async () => {
      const report = await runPreflight({ repoUrl: s.repoUrl, mcpUrl: s.mcpUrl });
      expect(report.schemaVersion).toBe("1.0");
      expect(report.score.total).toBeGreaterThanOrEqual(0);
      expect(report.score.total).toBeLessThanOrEqual(100);
      expect(report.tools.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      if (s.mcpUrl?.includes("context7")) {
        const auth = await probeAuth(s.mcpUrl);
        expect(auth.authorizationBaseUrl).toContain("context7.com");
      }
      if (s.repoUrl.includes("chrome-devtools")) {
        const repo = await scanGithubRepo("ChromeDevTools/chrome-devtools-mcp");
        expect(repo.hasReadme).toBe(true);
      }
    });
  }
});
