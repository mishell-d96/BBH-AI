# Secrets Exposure — Deep Reference

Authorized bug-bounty use only. Doctrine: validate minimally to prove a secret is **live and privileged**, then stop. Never use a found secret to read, modify, or exfiltrate real data beyond a single identity/scope check. Always redact secrets in artifacts.

---

## 1. Where secrets leak (sources)

### Bundled / client-side JavaScript
Modern SPAs inline config and "env" vars into the JS bundle. Build-time env injection (`REACT_APP_*`, `VUE_APP_*`, `NEXT_PUBLIC_*`, `process.env.*`) frequently leaks keys developers assumed were server-side. Mine every `main.*.js`, `vendor.*.js`, webpack chunk, and inline `<script>`.

Grep targets: `api_key`, `apikey`, `secret`, `token`, `Authorization`, `Bearer `, `aws_access_key_id`, `client_secret`, `private_key`, `BEGIN RSA/EC/OPENSSH PRIVATE KEY`, `xoxb-`, `xoxp-`, `sk_live_`, `sk-`, `AKIA`, `AIza`, `ghp_`, `glpat-`.

### Source maps
A reachable `.map` (e.g. `main.js.map`, referenced by `//# sourceMappingURL=`) reconstructs the *original* unminified source — comments, variable names, and inlined secrets the minified bundle hid.
- Reconstruct: **sourcemapper** (`sourcemapper -url https://t/static/js/main.js.map -output ./src`), or `npx source-map` / `unwebpack-sourcemap`.
- Even when not directly linked, try appending `.map` to each JS URL.

### Exposed VCS directories (.git/.svn/.hg)
A misconfigured server serving the repo metadata directory leaks full source + history.
- Confirm: `GET /.git/HEAD` returns `ref: refs/heads/main` (200, not the app HTML). Also probe `/.git/config`, `/.git/logs/HEAD`.
- Dump: **git-dumper** (`git-dumper https://target/.git/ ./out`) or **GitHacker** (multi-threaded, restores stash/branches/tags).
- Then: `git log --all -p`, `git stash list`, check deleted/old blobs — secrets are often committed then "removed" but remain in history.

### Config / backup files
Fuzz for `.env`, `.env.local`, `config.php.bak`, `settings.py`, `web.config`, `application.yml`, `*.old`, `*.zip`, `*.tar.gz`, `*.sql`, `docker-compose.yml`, `.npmrc`, `.dockercfg`, `id_rsa`.

### Public repos & commit history
Org GitHub/GitLab repos, forks, gists, and **full commit history** of public/leaked repos. Wayback/archive snapshots may preserve secrets long since removed from live pages.

---

## 2. Tooling

| Tool | Use |
|------|-----|
| **trufflehog** | Regex + entropy + **built-in live verification** of many providers. `trufflehog filesystem ./out --only-verified`; `trufflehog git file://./repo`; `trufflehog github --org=acme --only-verified`. |
| **gitleaks** | Fast regex/entropy over git history & files. `gitleaks detect --source ./repo -v`; `gitleaks dir ./js`. |
| **git-dumper** / **GitHacker** | Reconstruct repo from exposed `/.git/`. |
| **sourcemapper** / **unwebpack-sourcemap** | Rebuild source from `.map` files. |
| **LinkFinder** / **JSluice** / **SecretFinder** | Extract endpoints, params, and secret patterns from JS. |
| **GitHub dorking** | `org:"acme" /AKIA[0-9A-Z]{16}/`, `org:"acme" (AWS_SECRET_ACCESS_KEY)`, `"sk_live_"`, `xoxb-`, `glpat-`. |

GitHub dork patterns (per Intigriti guide): scope to `org:"target"` and search provider key regexes (OpenAI `sk-[A-Za-z0-9]{20,}`, Stripe, SendGrid, Slack, AWS, Azure, Cloudflare, GitHub PATs).

---

## 3. Provider validation — the ONE minimal check

Run a single identity/scope call. Confirm live + privilege level, then stop. Do not enumerate, download, or modify data.

| Provider | Key shape | Minimal validation (one call) |
|----------|-----------|-------------------------------|
| **AWS** | `AKIA…` + secret | `AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… aws sts get-caller-identity` (returns ARN/account — no data touched) |
| **GCP service acct** | `*.json` key | `gcloud auth activate-service-account --key-file=sa.json && gcloud auth print-access-token` |
| **GCP API key** | `AIza…` | depends on enabled API; e.g. Maps static endpoint below. Treat as low unless abuse shown. |
| **Azure** | client_id/secret/tenant | `az login --service-principal -u <id> -p <secret> --tenant <tenant>` |
| **GitHub** | `ghp_`, `gho_`, `github_pat_` | `curl -s -H "Authorization: token TOKEN" https://api.github.com/user` (or `/user/orgs`) |
| **GitLab** | `glpat-` | `curl -s --header "PRIVATE-TOKEN: TOKEN" https://gitlab.com/api/v4/user` |
| **Slack** | `xoxb-`/`xoxp-`/`xoxa-` | `curl -s "https://slack.com/api/auth.test?token=TOKEN"` |
| **Stripe (secret)** | `sk_live_`, `rk_live_` | `curl https://api.stripe.com/v1/balance -u sk_live_…:` (trailing colon) |
| **Twilio** | SID `AC…` + auth token | `curl -s https://api.twilio.com/2010-04-01/Accounts.json -u SID:TOKEN` |
| **SendGrid** | `SG.…` | `curl -s https://api.sendgrid.com/v3/scopes -H "Authorization: Bearer SG.…"` |
| **Mapbox (secret)** | `sk.…` | `curl -s "https://api.mapbox.com/tokens/v2?access_token=sk.…"` |
| **Google Maps** | `AIza…` (browser) | `curl "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key=KEY"` — proves valid, but see publishable note |

Prefer letting **trufflehog `--only-verified`** do verification automatically where supported, to minimize manual calls.

---

## 4. SECRET vs PUBLISHABLE (avoid false positives)

| Provider | SECRET (report if live+privileged) | PUBLISHABLE / client-side by design (NOT a finding alone) |
|----------|-----------------------------------|-----------------------------------------------------------|
| Stripe | `sk_live_`, `rk_live_`, restricted keys | `pk_live_`, `pk_test_` publishable keys |
| Mapbox | `sk.…` secret token | `pk.…` public token |
| Google | service-account JSON, OAuth client_secret | `AIza…` browser/Maps keys (only a finding with demonstrated abuse — e.g. unrestricted + billable API) |
| Firebase | Admin SDK / service account | Web config `apiKey` (public by design; report only with real auth/rules bypass) |
| GitHub | `ghp_`/`github_pat_` with scopes | n/a |
| Algolia | Admin API key | Search-only API key |
| reCAPTCHA | secret key | site key |

Rule of thumb: if the vendor documents the key as safe to ship in client code, it is **not** a secret leak by itself. Escalate only with concrete, validated abuse.

---

## 5. Chaining for impact
- **AWS/GCP/Azure creds** (validated via `sts get-caller-identity` / `print-access-token`) → `/cloud-storage-misconfig`, infra enumeration, role/privilege analysis. Stop at identity proof; don't list/read buckets beyond confirming access exists.
- **App API token / session secret** → `/access-control-idor`, account takeover, privileged actions.
- **JWT signing key / HMAC secret** → `/jwt`: forge tokens, escalate roles, impersonate users.
- **Source disclosure (.git, source maps)** → feed reconstructed code back to `/recon-mapper` to discover more endpoints, params, and additional secrets.

---

## 6. Responsible handling & redaction
- Make the **minimum** number of calls — ideally one identity check per key.
- **Never** read, modify, delete, or exfiltrate real data; do not send emails/SMS, do not spend money/credits, do not pivot into production systems.
- In `./_EXPLOIT/` and the report: **redact** every secret. Show only provider + format + last 1-4 chars (`AKIA…REDACTED`, `xoxb-…3f2a`). Record the source URL/file/line or commit hash and the (redacted) validation response.
- Hold the live secret only in memory for the validation call; do not write it to disk/logs. Flag for the program to rotate it.
- Disclose the source location so the team can remediate.

---

## 7. Prevention (for the report)
- Keep secrets server-side; never inline real secrets into client bundles or `*_PUBLIC_*`/`REACT_APP_*` build vars.
- Do not deploy `.map` files to production (or restrict them).
- Block web access to `/.git`, `/.svn`, `.env`, backups at the server/CDN.
- Pre-commit + CI secret scanning (gitleaks/trufflehog); purge history (`git filter-repo` / BFG) and **rotate** any exposed key — removal alone is insufficient.
- Scope/restrict keys (HTTP referrer, IP, API restrictions) and prefer short-lived/credentials with least privilege.

---

## 8. Sources
- Intigriti — Hunting for secrets in bug bounty targets: https://www.intigriti.com/researchers/blog/hacking-tools/hunting-for-secrets-in-bug-bounty-targets
- Streaak/keyhacks (per-provider validation commands): https://github.com/streaak/keyhacks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- gitleaks: https://github.com/gitleaks/gitleaks
- git-dumper: https://github.com/arthaud/git-dumper
- GitHacker: https://github.com/WangYihang/GitHacker
- LinkFinder: https://github.com/GerbenJavado/LinkFinder
- JSluice: https://github.com/BishopFox/jsluice
- Hunting API Keys in JavaScript Files (Medusa): https://medusa0xf.medium.com/hunting-api-keys-in-javascript-files-a-bug-hunters-guide-01940b7dd6ef
- Finding and Exploiting Leaked .git/ Directories (Medusa): https://medusa0xf.medium.com/bug-bounty-guide-finding-and-exploiting-leaked-git-directories-1e05dc520bf5
- Source code disclosure via exposed .git folder (Pentester Land): https://pentester.land/blog/source-code-disclosure-via-exposed-git-folder/
- AWS STS get-caller-identity: https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html
- Stripe API keys (publishable vs secret): https://docs.stripe.com/keys
