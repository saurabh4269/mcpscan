# MCPScan

Free, public directory of MCP servers with transparent security & trust scores. Recrawled daily on `main`; the static site is built with `python3 scripts/build.py` and published to the **`gh-pages` branch** by the existing external daily job (not GitHub Actions Pages deploy).

Live: https://saurabh4269.github.io/mcpscan/

## MCP Security Preflight (new)

Paste a **GitHub repo** on the [Preflight page](https://saurabh4269.github.io/mcpscan/preflight.html) for an in-browser report (auth checklist items that need a live URL are marked; use the CLI for those).

For **remote MCP endpoints** (OAuth metadata, live `tools/list`, deterministic security score):

```bash
# From npm (when published)
npx mcp-preflight --mcp https://mcp.example.com/mcp --repo https://github.com/org/server

# From this repository
npm ci --prefix packages/mcp-preflight
npm run build --prefix packages/mcp-preflight
npm run preflight --prefix packages/mcp-preflight -- --mcp https://mcp.context7.com/mcp --json
```

Reports include:

1. **Auth** — RFC 9728 protected-resource metadata, authorization-server discovery (RFC 8414 / OIDC), Client ID Metadata Documents or optional DCR, plus scope heuristics ([MCP authorization draft](https://modelcontextprotocol.io/specification/draft/basic/authorization)).
2. **Tool risk map** — read / write / exec / network heuristics and lethal-trifecta flags (private data + untrusted input + egress/exec).
3. **Prompt-injection scan** — suspicious patterns in tool names/descriptions plus a SHA-256 tool-list fingerprint for change detection.
4. **Directory readiness** — checklist aligned with [Anthropic MCP connector](https://docs.anthropic.com/en/docs/agents-and-tools/mcp-connector) and [OpenAI MCP](https://platform.openai.com/docs/mcp) public guidance.
5. **Deterministic score** — same inputs produce the same score breakdown on every run.

### GitHub Action (PR comments)

```yaml
- uses: saurabh4269/mcpscan@main
  with:
    repo-url: ${{ github.repository }}
    mcp-url: https://mcp.example.com/mcp
```

Or reference `action.yml` in this repo from your workflow.

### Development

- `scripts/crawl.py` — discovery + scoring (GitHub, official list, npm, OSV.dev)
- `scripts/build.py` — static site generator (`dist/`, including `preflight.html` and `preflight/preflight-browser.js`)
- `ops/daily.yml` — reference build-only workflow (manual); does not deploy Pages
- `.github/workflows/preflight.yml` — PR tests only
- `packages/mcp-preflight` — CLI + shared check library
- `npm test --prefix packages/mcp-preflight` — unit + integration tests (hits public Context7, Chrome DevTools MCP, Playwright MCP)

Sponsorship / contact: saurabh42@mail.grokbot.com
