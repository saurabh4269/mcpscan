#!/usr/bin/env python3
import json, os, html, shutil
D = json.load(open("data/servers.json")); E = html.escape
OUT = "dist"; shutil.rmtree(OUT, ignore_errors=True); os.makedirs(OUT + "/s")
CONTACT = "saurabh42@mail.grokbot.com"
CSS = """body{font-family:system-ui,sans-serif;max-width:960px;margin:auto;padding:16px;color:#1b1f24;background:#fafbfc}
a{color:#0b5fff}header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}
.box{background:#fff;border:1px solid #dde;border-radius:10px;padding:14px;margin:14px 0}
.sp{border:2px dashed #f0a400;background:#fffbea}.sc{font-weight:700;padding:2px 8px;border-radius:6px;color:#fff}
.g{background:#1a7f37}.y{background:#bf8700}.r{background:#cf222e}table{width:100%;border-collapse:collapse}
td,th{padding:6px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}input,select{padding:8px;margin:4px}
.tag{font-size:12px;background:#eef;border-radius:4px;padding:1px 5px;margin-right:3px}"""
def cls(s): return "g" if s >= 70 else "y" if s >= 50 else "r"
def page(title, body, root=""):
    return f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{E(title)}</title><meta name=description content="MCPScan: security and trust scores for MCP servers"><style>{CSS}</style>
<header><h2><a href="{root}index.html" style="text-decoration:none">🛡️ MCPScan</a></h2><nav><a href="{root}index.html">Directory</a> · <a href="{root}methodology.html">Methodology</a></nav></header>
<div class="box sp"><b>Sponsor this site</b> — Your tool here, contact <a href="mailto:{CONTACT}?subject=MCPScan%20sponsorship">{CONTACT}</a></div>
{body}
<div class=box><b>Weekly MCP security digest</b> (coming soon). Want it? <a href="mailto:{CONTACT}?subject=Subscribe%20MCPScan%20digest">Email {CONTACT}</a> with subject "Subscribe".</div>
<footer><small>Updated daily · last crawl {E(D['generated_at'][:16].replace('T',' '))} UTC · scores are automated heuristics, not an audit · <a href="https://github.com/saurabh4269/mcpscan">source</a></small></footer></html>"""
rows = []
for s in D["servers"]:
    rows.append({"i": s["id"], "n": s["full_name"], "d": s["description"][:140], "s": s["score"], "st": s["stars"],
                 "l": s["language"] or "", "o": s["official_list"], "r": s["risky"], "v": len(s["vulns"])})
    b = s["breakdown"]
    tr = "".join(f"<tr><td>{k.replace('_',' ')}</td><td>{v}</td></tr>" for k, v in b.items())
    vl = "".join(f"<li>{E(v['package'])}@{E(v['version'])}: <a href='https://osv.dev/vulnerability/{E(v['id'])}'>{E(v['id'])}</a></li>" for v in s["vulns"]) or "<li>None found in declared, pinned dependencies</li>"
    body = f"""<div class=box><h1>{E(s['full_name'])} <span class="sc {cls(s['score'])}">{s['score']}/100</span></h1><p>{E(s['description'])}</p>
<p><a href="{E(s['url'])}">GitHub</a>{' · npm: '+E(s['npm']) if s['npm'] else ''} · ⭐ {s['stars']} · {E(s['language'] or '')} · license {E(s['license'] or 'none')} · last push {s['days_since_push']} days ago{' · <b>archived</b>' if s['archived'] else ''}{' · listed in official MCP servers README' if s['official_list'] else ''}</p></div>
<div class=box><h3>Score breakdown</h3><table><tr><th>Factor</th><th>Points</th></tr>{tr}</table><p><small>See <a href="../methodology.html">methodology</a> for max points per factor.</small></p></div>
<div class=box><h3>Signals</h3><ul><li>Risky patterns detected: {E(', '.join(s['risky']) or 'none')}</li><li>Package provenance/attestations: {'yes' if s['provenance'] else 'no'}</li><li>CI workflows: {'yes' if s['has_ci'] else 'no'}</li><li>SECURITY.md: {'yes' if s['has_security_policy'] else 'no'}</li><li>Dependencies checked against OSV.dev: {s['deps_checked']}</li></ul><h4>Known vulnerabilities</h4><ul>{vl}</ul></div>"""
    open(f"{OUT}/s/{s['id']}.html", "w").write(page(s["full_name"] + " – MCPScan", body, "../"))
idx = f"""<div class=box><h1>Security & trust scores for {D['count']} MCP servers</h1><p>An automated, transparent directory. Every server is re-crawled daily from GitHub, the official MCP servers list and npm, and scored on maintenance, license, popularity, known dependency vulns (OSV.dev), supply-chain signals and risky code patterns.</p>
<input id=q placeholder="Search…" size=30><select id=f><option value="">All</option><option value=o>Official list</option><option value=shell_exec>Uses shell exec</option><option value=v>Has known vulns</option><option value=clean>No risky patterns</option></select><select id=so><option value=s>Sort: score</option><option value=st>Sort: stars</option></select></div>
<div class=box><table><thead><tr><th>Score</th><th>Server</th><th>⭐</th><th>Flags</th></tr></thead><tbody id=t></tbody></table></div>
<script>const D={json.dumps(rows)};const c=s=>s>=70?'g':s>=50?'y':'r';
function R(){{const q=document.getElementById('q').value.toLowerCase(),f=document.getElementById('f').value,so=document.getElementById('so').value;
let x=D.filter(s=>(s.n+' '+s.d).toLowerCase().includes(q)&&(!f||(f=='o'?s.o:f=='v'?s.v>0:f=='clean'?!s.r.length:s.r.includes(f))));x.sort((a,b)=>b[so]-a[so]);
document.getElementById('t').innerHTML=x.map(s=>`<tr><td><span class="sc ${{c(s.s)}}">${{s.s}}</span></td><td><a href="s/${{s.i}}.html">${{s.n}}</a><br><small>${{s.d.replace(/</g,'&lt;')}}</small></td><td>${{s.st}}</td><td>${{s.r.map(r=>`<span class=tag>${{r}}</span>`).join('')}}${{s.v?`<span class=tag>${{s.v}} vulns</span>`:''}}</td></tr>`).join('')}}
['q','f','so'].forEach(i=>document.getElementById(i).oninput=R);R();</script>"""
open(f"{OUT}/index.html", "w").write(page("MCPScan – MCP server security directory", idx))
meth = """<div class=box><h1>Methodology</h1><p>Each score is 0–100, the sum of six factors. It's computed automatically from public data and is a heuristic signal, not a security audit.</p>
<table><tr><th>Factor</th><th>Max</th><th>How</th></tr>
<tr><td>Maintenance</td><td>25</td><td>Days since last push: ≤30→25, ≤90→18, ≤180→10, ≤365→4, else 0. Archived repos get 0.</td></tr>
<tr><td>License</td><td>10</td><td>Recognised SPDX license 10; unrecognised/other 3; none 0.</td></tr>
<tr><td>Popularity</td><td>15</td><td>Stars: ≥1000→15, ≥300→12, ≥100→9, ≥25→6, ≥5→3.</td></tr>
<tr><td>Dependencies</td><td>20</td><td>Pinned versions from package.json, requirements.txt, pyproject.toml and go.mod checked against the <a href="https://osv.dev">OSV.dev</a> API. 0 vulns→20, ≤2→12, ≤5→5, else 0.</td></tr>
<tr><td>Supply chain</td><td>10</td><td>npm provenance attestations 6, CI workflows 2, SECURITY.md 2.</td></tr>
<tr><td>Risky patterns</td><td>20</td><td>Regex scan of the top-level source files. Deductions: shell exec −8, eval/dynamic code −6, filesystem writes −3, outbound network −3. Many legitimate servers need these, so treat this as "capabilities to review" rather than "malicious".</td></tr></table>
<h3>Discovery</h3><p>GitHub search (topic:mcp-server, topic:model-context-protocol, topic:mcp, "mcp server"), repos linked from the official <a href="https://github.com/modelcontextprotocol/servers">modelcontextprotocol/servers</a> README, and npm packages with keyword mcp-server. Forks are skipped; the top servers by stars are scanned. The crawl runs daily on GitHub Actions.</p>
<p>Spotted a wrong score? Open an issue on <a href="https://github.com/saurabh4269/mcpscan">GitHub</a>.</p></div>"""
open(f"{OUT}/methodology.html", "w").write(page("Methodology – MCPScan", meth))
open(f"{OUT}/.nojekyll", "w").write("")
print("built", D["count"])
