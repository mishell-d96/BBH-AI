---
name: secrets-exposure
description: "Find & validate exposed secrets — API keys, tokens, cloud creds, private keys — in client JS, source maps, exposed .git/.svn, config/backup files, public repos. Use for bundled JS/webpack chunks, REACT_APP_/VUE_APP_ vars, .map files, hardcoded AWS/GCP keys, Authorization/Bearer/api_key strings."
---

# Secrets Exposure

> **Prereq — surfaced during mapping:** This class is driven by `/recon-mapper`'s asset inventory (Phase 1/2 JS files, archived URLs, OSINT/repo leads). Run the map first and mine the JS/endpoints/repos it discovers. Validate a found secret minimally, then chain its privileges into real impact.

## When to test
- Recon surfaced bundled JS (`main.*.js`, webpack chunks, `vendor.js`) or inline scripts.
- `.map` source maps are reachable (`main.js.map`, `app.*.js.map`).
- `/.git/`, `/.svn/`, `/.hg/` directories or config/backup files (`.env`, `config.php.bak`, `*.zip`, `*.sql`) are exposed.
- Target org has public GitHub/GitLab repos, gists, or commit history.
- You see `REACT_APP_*`, `VUE_APP_*`, `Authorization`, `Bearer`, `api_key`, `aws_access_key_id`, `BEGIN PRIVATE KEY`, or high-entropy strings.

## Impact & priority
Be HONEST — finding a string that *looks* like a secret is nothing on its own.
- **High:** a secret you VALIDATED as **live AND privileged** — e.g. AWS creds that pass `sts get-caller-identity` and reach S3/infra, an app token granting account/data access, a JWT signing key. These chain to cloud/account/data compromise.
- **Medium:** live secret with limited/unclear scope, or source code disclosure via `.git`/source maps that reveals further attack surface.
- **Low / noise:** publishable client-side keys (Stripe `pk_`, Google Maps browser keys with no abuse), dead/revoked keys, or any "secret" with no proven access. Do not report these as secret leaks.

## Detection
- **Bundled JS / source maps:** download all JS; reconstruct originals from `.map` files with **sourcemapper** / `unpacker`. Extract endpoints+secrets with **LinkFinder**, **JSluice**, **SecretFinder**.
- **Exposed VCS:** confirm `/.git/HEAD` returns `ref: refs/heads/...`, then dump with **git-dumper** / **GitHacker**; inspect full history (`git log -p`) for committed-then-removed secrets.
- **Config/backup files:** fuzz for `.env`, `*.bak`, `*.old`, `*.zip`, `*.sql`, `config.*`.
- **Repos & history:** GitHub/GitLab org dorking + scan clones and full history.
- **Regex/entropy at scale:** **trufflehog** (has built-in live verification) and **gitleaks** over JS, dumped repos, and archived URLs.

### No-special-tooling fallback (only curl/grep/jq/python3)
trufflehog/gitleaks/git-dumper/sourcemapper may be ABSENT — they're **if-installed accelerators**. **Verify tool presence first (`command -v trufflehog gitleaks git-dumper`); the curl/regex path below always works.**
```bash
# 1) JS secret regex sweep — high-confidence provider prefixes only (low FP)
curl -s https://TARGET/static/main.js | grep -ioE '(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]+|glpat-[0-9A-Za-z_-]{20})'
# sweep every bundle: for j in $(curl -s https://TARGET/ | grep -oE 'src="[^"]+\.js"' | cut -d'"' -f2); do curl -s "https://TARGET/$j" | grep -ioE '(AKIA...|ghp_...)' ; done

# 2) .git fallback — confirm exposure, then pull objects manually (no git-dumper)
curl -s https://TARGET/.git/HEAD          # expect: ref: refs/heads/main
curl -s https://TARGET/.git/config        # remote URL, creds-in-url
curl -s -o /tmp/git_index https://TARGET/.git/index   # parse with: git ls-files --stage (in a stub repo) or python3 dulwich
# fetch a known object once confirmed: curl -s https://TARGET/.git/objects/<2>/<38> | python3 -c 'import sys,zlib;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))'

# 3) source-map reconstruct — recover original source/secrets from .js.map
npx source-map cat main.js.map 2>/dev/null \
 || curl -s https://TARGET/static/main.js.map \
    | python3 -c 'import sys,json,os;m=json.load(sys.stdin);[ (os.makedirs(os.path.dirname(p) or ".",exist_ok=True), open(p,"w").write(c)) for p,c in zip(m["sources"],m.get("sourcesContent") or []) if c]'
```

## Validation & exploitation
Identify the provider from the key format, then make exactly **ONE** minimal authenticated call to confirm the key is live and learn its scope. **Stop at proof — never read/write/exfiltrate real data.**
- AWS — `aws sts get-caller-identity`
- GCP service account — `gcloud auth print-access-token`
- GitHub token — `GET /user` (or `/user/orgs`)
- Slack — `auth.test`
- Stripe (secret `sk_`/`rk_`) — `GET /v1/balance`
- Twilio — `GET /2010-04-01/Accounts.json`
- SendGrid — `GET /v3/scopes`
See `reference.md` for exact commands per provider and SECRET-vs-PUBLISHABLE rules.

## Chain for impact
- **Cloud key (AWS/GCP/Azure)** → `/cloud-storage-misconfig` and infra enumeration (scope only).
- **App token / API key** → `/access-control-idor` or account takeover.
- **JWT signing key / HMAC secret** → `/jwt` (forge tokens, privilege escalation).
- **Source code from `.git`/maps** → feed back into `/recon-mapper` for more endpoints and secrets.

## Minimal PoC
Capture two things only:
1. The **source location** of the secret (exact URL/file + line, or `.git` commit hash).
2. The **single validation response** proving it is live and privileged (e.g. `sts get-caller-identity` ARN, `auth.test` workspace, `/user` login).

For `./_EXPLOIT/`: log the finding **with the secret REDACTED** (`AKIA…REDACTED`, last 4 chars max). Keep the unredacted value only transiently for the one validation call; never store it.

## Don't report as noise
- Publishable/client-side-by-design keys: Stripe `pk_live`/`pk_test` publishable, Google Maps/Firebase browser keys (unless you demonstrate concrete abuse like billing or unrestricted API misuse).
- Dead, revoked, or rotated keys that fail validation.
- High-entropy strings with no identified provider and no proven access.
- "Secrets" already documented as intentionally public.

## Deep reference
See `reference.md` for full tooling, per-provider minimal checks, SECRET-vs-PUBLISHABLE tables, chaining, redaction, and prevention. Key sources: Intigriti "Hunting for secrets" guide, Streaak/keyhacks, TruffleHog & gitleaks docs.
