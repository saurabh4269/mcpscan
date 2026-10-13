#!/usr/bin/env python3
"""MCPScan crawler: discovers MCP servers and computes a transparent trust score."""
import json, os, re, sys, time, urllib.request, urllib.parse, datetime, base64
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
NOW = datetime.datetime.now(datetime.timezone.utc)
MAX = int(os.environ.get("MAX_SERVERS", "250"))

def get(url, data=None, headers=None, raw=False):
    h = {"User-Agent": "mcpscan", **(headers or {})}
    if "api.github.com" in url and TOKEN: h["Authorization"] = f"Bearer {TOKEN}"
    body = None
    if data is not None:
        body = json.dumps(data).encode(); h["Content-Type"] = "application/json"
    for i in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, body, h), timeout=30) as r:
                b = r.read(); return b.decode("utf-8", "replace") if raw else json.loads(b)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429): time.sleep(20 * (i + 1)); continue
            return None
        except Exception:
            time.sleep(3)
    return None

def gh_search(q, pages=3):
    out = []
    for p in range(1, pages + 1):
        r = get("https://api.github.com/search/repositories?" + urllib.parse.urlencode({"q": q, "sort": "stars", "per_page": 100, "page": p}))
        if not r or not r.get("items"): break
        out += r["items"]; time.sleep(2)
    return out

def discover():
    repos = {}
    for q in ["topic:mcp-server", "topic:model-context-protocol", "topic:mcp", "mcp server in:name,description"]:
        for it in gh_search(q):
            repos.setdefault(it["full_name"].lower(), it)
    # official list
    md = get("https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md", raw=True) or ""
    official = set(m.lower() for m in re.findall(r"github\.com/([\w.-]+/[\w.-]+?)(?:[/#)\s]|\.git)", md))
    official = {o for o in official if not o.startswith("modelcontextprotocol/")}
    for full in list(official)[:150]:
        if full not in repos:
            it = get(f"https://api.github.com/repos/{full}")
            if it and "full_name" in it: repos[it["full_name"].lower()] = it
    # npm
    npm = {}
    r = get("https://registry.npmjs.org/-/v1/search?text=keywords:mcp-server&size=250") or {}
    for o in r.get("objects", []):
        p = o["package"]; link = (p.get("links") or {}).get("repository") or ""
        m = re.search(r"github\.com/([\w.-]+/[\w.-]+)", link)
        if m: npm.setdefault(m.group(1).removesuffix(".git").lower(), p["name"])
    for full in list(npm)[:80]:
        if full not in repos:
            it = get(f"https://api.github.com/repos/{full}")
            if it and "full_name" in it: repos[it["full_name"].lower()] = it
    return repos, official, npm

RISKY = {
    "shell_exec": r"child_process|execSync|spawn\(|subprocess\.|os\.system|exec\.Command|shell=True",
    "network": r"fetch\(|axios|requests\.(get|post)|httpx|urllib\.request|http\.Get|aiohttp",
    "filesystem_write": r"writeFile|fs\.write|open\([^)]*['\"]w|os\.remove|unlink\(|rmSync",
    "eval": r"\beval\(|new Function\(|\bexec\(",
}

def code_scan(full, branch):
    tree = get(f"https://api.github.com/repos/{full}/git/trees/{branch}?recursive=1") or {}
    files = [t["path"] for t in tree.get("tree", []) if t.get("type") == "blob"]
    src = [f for f in files if re.search(r"\.(ts|js|mjs|py|go|rs)$", f) and not re.search(r"test|node_modules|dist/|example", f, re.I)]
    src.sort(key=lambda f: (f.count("/"), len(f)))
    found = set(); text = ""
    for f in src[:6]:
        t = get(f"https://raw.githubusercontent.com/{full}/{branch}/{f}", raw=True) or ""
        text += t[:200000]
    for k, rx in RISKY.items():
        if re.search(rx, text): found.add(k)
    manifests = {}
    for f in ("package.json", "requirements.txt", "pyproject.toml", "go.mod"):
        if f in files:
            manifests[f] = get(f"https://raw.githubusercontent.com/{full}/{branch}/{f}", raw=True) or ""
    has_ci = any(f.startswith(".github/workflows/") for f in files)
    has_security = any(f.lower() in ("security.md", ".github/security.md") for f in files)
    prov = any(re.search(r"provenance|sigstore|cosign|attest", manifests.get("package.json", "") ) for _ in [0])
    for f in files:
        if f.startswith(".github/workflows/"):
            pass
    return found, manifests, has_ci, has_security, prov, files

def deps(manifests):
    out = []
    pj = manifests.get("package.json")
    if pj:
        try:
            d = json.loads(pj).get("dependencies", {}) or {}
            for n, v in d.items():
                m = re.search(r"\d+\.\d+\.\d+", str(v))
                if m: out.append(("npm", n, m.group(0)))
        except Exception: pass
    for f in ("requirements.txt", "pyproject.toml"):
        for n, v in re.findall(r"['\"]?([A-Za-z0-9_.-]+)\s*(?:==|>=|~=)\s*([0-9][0-9.]*)", manifests.get(f, "")):
            out.append(("PyPI", n, v))
    for n, v in re.findall(r"^\s*([\w./-]+\.[\w./-]+)\s+v([0-9][\w.-]*)", manifests.get("go.mod", ""), re.M):
        out.append(("Go", n, "v" + v))
    return out[:60]

def osv(deplist):
    if not deplist: return []
    q = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in deplist]}
    r = get("https://api.osv.dev/v1/querybatch", data=q) or {}
    vulns = []
    for (e, n, v), res in zip(deplist, r.get("results", [])):
        for x in res.get("vulns", []) or []:
            vulns.append({"package": n, "version": v, "id": x["id"]})
    return vulns

def npm_provenance(name):
    if not name: return False
    r = get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/latest") or {}
    return bool((r.get("dist") or {}).get("attestations"))

def score(s):
    b = {}
    days = s["days_since_push"]
    b["maintenance"] = 25 if days <= 30 else 18 if days <= 90 else 10 if days <= 180 else 4 if days <= 365 else 0
    b["license"] = 10 if s["license"] and s["license"] not in ("NOASSERTION", "Other") else 3 if s["license"] else 0
    st = s["stars"]
    b["popularity"] = 15 if st >= 1000 else 12 if st >= 300 else 9 if st >= 100 else 6 if st >= 25 else 3 if st >= 5 else 0
    n = len(s["vulns"])
    b["dependencies"] = 20 if n == 0 else 12 if n <= 2 else 5 if n <= 5 else 0
    b["supply_chain"] = (6 if s["provenance"] else 0) + (2 if s["has_ci"] else 0) + (2 if s["has_security_policy"] else 0)
    pen = {"shell_exec": 8, "eval": 6, "filesystem_write": 3, "network": 3}
    b["risky_patterns"] = max(0, 20 - sum(pen[k] for k in s["risky"]))
    if s["archived"]: b["maintenance"] = 0
    return sum(b.values()), b

def main():
    repos, official, npm = discover()
    items = sorted(repos.values(), key=lambda r: -r.get("stargazers_count", 0))
    items = [r for r in items if not r.get("fork")][:MAX]
    print(f"discovered {len(repos)}, scanning {len(items)}", file=sys.stderr)
    out = []
    for i, r in enumerate(items):
        full = r["full_name"]
        try:
            risky, man, ci, sec, prov, _ = code_scan(full, r.get("default_branch", "main"))
            npmname = npm.get(full.lower())
            if not npmname and man.get("package.json"):
                try: npmname = json.loads(man["package.json"]).get("name")
                except Exception: pass
            prov = prov or npm_provenance(npmname) if npmname else prov
            dl = deps(man); v = osv(dl)
        except Exception as e:
            print("err", full, e, file=sys.stderr); risky, ci, sec, prov, dl, v, npmname = set(), False, False, False, [], [], None
        pushed = datetime.datetime.fromisoformat(r["pushed_at"].replace("Z", "+00:00"))
        s = {
            "id": full.replace("/", "__").lower(), "name": r["name"], "full_name": full,
            "url": r["html_url"], "description": (r.get("description") or "")[:300],
            "stars": r.get("stargazers_count", 0), "language": r.get("language"),
            "license": (r.get("license") or {}).get("spdx_id"), "archived": r.get("archived", False),
            "pushed_at": r["pushed_at"], "days_since_push": (NOW - pushed).days,
            "official_list": full.lower() in official, "npm": npmname,
            "provenance": bool(prov), "has_ci": ci, "has_security_policy": sec,
            "risky": sorted(risky), "deps_checked": len(dl), "vulns": v[:50],
            "topics": r.get("topics", [])[:8],
        }
        s["score"], s["breakdown"] = score(s)
        out.append(s)
        if i % 20 == 0: print(i, full, s["score"], file=sys.stderr)
    out.sort(key=lambda s: -s["score"])
    json.dump({"generated_at": NOW.isoformat(), "count": len(out), "servers": out}, open("data/servers.json", "w"), indent=1)
    print("wrote", len(out))

if __name__ == "__main__": main()
