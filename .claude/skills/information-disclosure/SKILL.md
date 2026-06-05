---
name: information-disclosure
description: "Unintentional leaks of sensitive data — secrets, source, PII, internal infra. Use for verbose errors/stack traces, debug pages, robots.txt hints, backup/source files (.bak/.old/.swp/.zip), exposed .git/.svn, source maps (.js.map), version banners, directory listing. Strict anti-noise."
---

# Information Disclosure

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


A site unintentionally reveals sensitive information: user data/PII, secrets, source code, or technical infrastructure. The bounty bar is IMPACT — a leak only matters if you can show what an attacker does with it.

## When to test
- Verbose error pages / stack traces leaking paths, queries, framework + versions
- Debug consoles or diagnostic endpoints (`/debug`, `/trace`, `/actuator`, `/_profiler`, phpinfo)
- `robots.txt` / `sitemap.xml` pointing at hidden or admin paths
- Backup & source artifacts (`.bak`, `.old`, `~`, `.swp`, `index.php.txt`, `app.zip`)
- Exposed VCS dirs (`/.git/`, `/.svn/`), source maps (`*.js.map`)
- Hardcoded API keys / credentials / tokens in JS, comments, or config files
- Directory listing enabled; revealing HTML/JS developer comments

## Impact & priority (be honest)
- HIGH signal: live credentials/API keys/tokens, PII at scale, full source/proprietary logic, private keys, internal creds in debug output, `.git` exposing secrets.
- MEDIUM: leaks that materially enable another proven bug (a parameter/ID that yields IDOR, a query in an error enabling SQLi).
- NOISE (usually NOT reportable on its own): server version banners, framework names, missing security headers, generic stack traces with nothing sensitive. See "Don't report as noise".

## Detection
- Fuzz parameters with unexpected types/values; diff responses (status, length, time, error text) to surface distinct backend behavior.
- Content discovery for hidden dirs/backups/VCS (Burp **Discover content**, ffuf/feroxbuster with backup+VCS wordlists).
- Pull HTML/JS comments (Burp **Find comments**); scan JS bundles and `.map` files for keys, endpoints, internal hosts.
- Probe `TRACE` (echoes request, may reflect internal/auth headers) and verbose error triggers.
- Check `robots.txt`, `sitemap.xml`, well-known debug endpoints.

### Installed-tool oneshots (copy-paste)
```bash
# .git exposure probe — 200/304 on /.git/HEAD = dumpable repo (confirm "ref: refs/heads/...")
curl -s -o /dev/null -w '%{http_code}\n' https://TARGET/.git/HEAD

# source-map sweep — flag bundles shipping a .map (original source recoverable)
for j in $(katana -u https://TARGET -silent | grep -E '\.js$'); do
  curl -s -o /dev/null -w "%{http_code} $j.map\n" "$j.map"; done | grep '^200'

# backup/temp file fuzz — proven-disclosure extensions only; respect program rate cap
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -u https://TARGET/FUZZ -e .bak,.old,.zip,.swp,~ -mc 200 -rate <cap>
```

## Exploitation (turn a leak into impact)
- Keys/credentials/tokens -> authenticate to the API/backend and demonstrate a privileged action (read-only, minimal).
- Source / source maps -> read logic to find auth bypass, hardcoded secrets, hidden params.
- Leaked IDs/usernames/object refs -> chain into IDOR / account access.
- `.git` / `.svn` -> reconstruct repo, diff history for secrets and removed code.
- Error queries -> confirm SQLi/injection surface.
Always prove the chain; a raw leak with no demonstrated consequence is low/none.

## Common sources
Errors & stack traces; debug/diagnostic pages; `robots.txt`/`sitemap.xml`; backup & temp source files served as text; directory listings; exposed `.git`/`.svn`; source maps; HTML/JS developer comments; user/account pages leaking others' data via param tweaks.

## Minimal PoC (log proven finds to ./_EXPLOIT/)
Safe, minimal, just enough to prove it. Redact secrets to a few identifying chars — do not exfiltrate full datasets.
```bash
# Exposed git config / source proving disclosure
curl -s https://TARGET/.git/config

# Backup source served as text (reveals hardcoded secret)
curl -s https://TARGET/config.php.bak | grep -i -E 'key|secret|password' | head

# Source map leaking original source
curl -s https://TARGET/static/app.js.map | head -c 200

# Then prove impact (example): use a leaked key for ONE read-only call
curl -s -H "Authorization: Bearer <leaked_token_REDACTED>" https://TARGET/api/me
```
Capture: request, the leaked value (redacted), and the impact step. Handle any real PII/secret minimally — store only what proves the bug.

## Don't report as noise
This class is the #1 source of junk reports. Do NOT file:
- Server/framework version banners (`Server: nginx/1.x`, `X-Powered-By`) with no exploit.
- Missing security headers (HSTS, CSP, X-Frame-Options) as "info disclosure".
- Generic stack traces / error pages that reveal nothing sensitive or exploitable.
- `robots.txt` contents alone, or directory listing of public/non-sensitive files.
- Software version "disclosure" without a demonstrated known-CVE exploit on that version.
If you can't articulate concrete attacker impact, it isn't a finding.

## Deep reference
See `reference.md` for full source catalog, discovery tooling, impact chains, and prevention.
- https://portswigger.net/web-security/information-disclosure
- https://portswigger.net/web-security/information-disclosure/exploiting
