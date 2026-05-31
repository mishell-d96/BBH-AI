# Information Disclosure — Reference

Information disclosure (information leakage) is when a website unintentionally reveals sensitive information to its users — user/PII data, proprietary business data, or technical infrastructure details. Severity is driven by *impact*: leaked credentials/PII/source are high value; technical details (versions, paths) only matter if you can show an attacker doing something harmful with them.

Sources: https://portswigger.net/web-security/information-disclosure and https://portswigger.net/web-security/information-disclosure/exploiting

---

## 1. How these vulnerabilities arise
- **Internal content leaked to external users** — developer artifacts (comments, debug pages, backups, VCS dirs) left in production.
- **Misconfiguration** — security features disabled or insecurely set (verbose errors, directory listing, `TRACE` enabled, debug mode on).
- **Flawed design** — distinctive responses (status/length/time/error text) that enable enumeration of users, files, or behavior.

## 2. Common sources

### Files intended for web crawlers
- `robots.txt`, `sitemap.xml` often list directories admins want hidden from search engines — but they are directly requestable. Read them first; treat listed paths as discovery leads.

### Directory listings
- A web server may auto-list a directory's contents when no index page exists, exposing temp files, crash dumps, backups, or source not meant to be public. Listing of genuinely sensitive files = finding; listing of public assets = noise.

### Developer comments
- HTML/JS comments left in production can reveal hidden endpoints, internal hostnames, credentials, logic hints, or "TODO" disclosures. Often forgotten or left by someone unaware of the security implications.

### Error messages
- Verbose errors reveal: expected input types, technologies in use, version numbers, framework, file paths, and sometimes SQL queries. Different error text for different inputs is a behavioral oracle — useful for SQLi confirmation and username enumeration. The error wording/format itself can disclose the stack.

### Debugging data
- Debug logs and pages may contain session variables, backend/system credentials, file paths, SQL, keys, and server state. Look for separate debug log files and verbose diagnostic endpoints.

### User account / profile pages
- Pages exposing email, phone, API keys. Logic flaws (e.g. swapping an ID/username parameter) may let you view another user's data without full account takeover — overlaps with IDOR/access control.

### Backup & source files
- Editor/backup artifacts: `file.php~`, `file.php.bak`, `.old`, `.orig`, `.swp`, `index.php.txt`, archives (`.zip`, `.tar.gz`). The server may serve the source as text instead of executing it, exposing hardcoded API keys and credentials.

### Insecure configuration / dangerous methods
- `TRACE` echoes the request back and can reflect internal headers (e.g. auth/identity headers added by proxies). Default platform configs and overly permissive options frequently leak.

### Version control exposure
- Exposed `/.git/` (or `/.svn/`) lets an attacker download the full history. Diffs reveal removed code and hardcoded secrets that are no longer in the deployed source but persist in commits. Tools like git-dumper reconstruct the repo from an exposed `.git/`.

### Source maps
- `*.js.map` reverse-map minified bundles to original source, exposing logic, comments, internal endpoints, and sometimes secrets.

### Hardcoded credentials / API keys
- In JS bundles, source maps, comments, config files, backups, and VCS history. A live key is high-signal — prove it works with a single minimal authorized call.

### Subtle response / timing differences
- Differences in status code, response length, body, or response time across inputs are themselves a disclosure (an oracle) enabling enumeration. Diff systematically.

## 3. How to find them

### Burp Suite
- **Burp Scanner** flags leaks: private keys, emails, credit-card numbers, backup files, directory listings.
- **Engagement tools (right-click):**
  - **Search** — keyword/regex (including negative match) across traffic.
  - **Find comments** — extract developer comments from responses.
  - **Discover content** — enumerate unlinked directories and files.
- **Intruder** — fuzz parameters with wordlists; sort/compare by status, length, time to spot anomalies.

### Other content discovery
- `ffuf` / `feroxbuster` / `dirsearch` / `gobuster` with wordlists that include backup extensions and VCS paths (`/.git/`, `/.svn/`, `.bak`, `~`, `.old`).
- Specialized: git-dumper (rebuild from exposed `.git`), source-map extractors, secret scanners (trufflehog/gitleaks) on downloaded JS/source.
- Manual: read `robots.txt`/`sitemap.xml`, inspect JS bundles + `.map`, trigger errors with malformed input, test `TRACE`.

## 4. Turning disclosure into real impact
The leak is the start, not the finish. Chains:
- **Credentials / API keys / tokens** -> authenticate and demonstrate one privileged, read-only action against the backend/API.
- **Source code / source maps** -> analyze for auth bypass, hidden parameters, more hardcoded secrets, logic flaws.
- **`.git` / `.svn`** -> reconstruct and diff history for secrets and removed sensitive code.
- **Leaked IDs / usernames / object references** -> IDOR / account enumeration / takeover.
- **Error-message queries / distinct behavior** -> confirm SQL injection or other injection surface.
- **Architecture/version + known CVE** -> only valuable if you actually demonstrate the matching exploit.

PortSwigger: technical-info disclosure "is often only of interest if you are able to demonstrate how an attacker could do something harmful with it."

## 5. Anti-noise discipline (critical)
Information disclosure is the #1 source of junk reports. The following, on their own, are NOT findings and annoy programs:
- Server/framework version banners (`Server`, `X-Powered-By`).
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.).
- Generic error pages / stack traces revealing nothing sensitive or exploitable.
- `robots.txt` contents disclosed; directory listing of public/non-sensitive content.
- "Software version disclosure" with no demonstrated exploit on that version.
Rule: if you cannot state a concrete attacker action enabled by the leak, do not report it.

## 6. Handling sensitive data (scope & safety)
- Stay strictly in scope; access only what's needed to prove the bug.
- Redact PII/secrets in PoCs to a few identifying characters; never exfiltrate or store full datasets.
- Use leaked credentials for the minimum read-only proof, never destructive or lateral actions.
- Log only proven, impactful findings to `./_EXPLOIT/` with request, redacted leak, and impact step.

## 7. Prevention (for write-ups / remediation advice)
- Train teams to recognize sensitive information; review security implications of every enabled feature and third-party config.
- Automate code audits to strip comments and debug artifacts before production.
- Use generic, non-revealing error messages; disable debug/diagnostic modes in production.
- Block dangerous methods (`TRACE`); disable directory listing; deny access to VCS dirs, backups, and source maps at the web-server layer.
- Understand defaults of any third-party tech you deploy.

## References
- https://portswigger.net/web-security/information-disclosure
- https://portswigger.net/web-security/information-disclosure/exploiting
