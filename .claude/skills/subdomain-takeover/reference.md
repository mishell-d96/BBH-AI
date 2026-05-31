# Subdomain Takeover — Deep Reference

Comprehensive companion to `SKILL.md`. Authorized, in-scope targets only. Proof must
be a harmless unique marker; never deface, never host real phishing, never submit the
PoC to web archives.

Primary sources:
- HackerOne, "A Guide To Subdomain Takeovers 2.0": https://www.hackerone.com/blog/guide-subdomain-takeovers-20
- EdOverflow / can-i-take-over-xyz (the canonical fingerprint matrix): https://github.com/EdOverflow/can-i-take-over-xyz
- OWASP Web Security Testing Guide — Test for Subdomain Takeover (WSTG-CONF-10): https://owasp.org/www-project-web-security-testing-guide/

---

## 1. How dangling DNS arises

A subdomain takeover is possible when a DNS record resolves to a third-party service
whose backing resource no longer exists (or was never created), and that service lets
anyone claim the name.

Typical lifecycle that creates the dangle:
1. A team points `docs.example.com` (CNAME) at a SaaS/cloud resource — an S3 bucket, a
   GitHub Pages repo, a Heroku app, an Azure App Service, a Netlify/Surge site, a
   Zendesk/Shopify tenant, etc.
2. The team later deletes the SaaS resource / cancels the account / tears down the app.
3. They forget to remove the DNS record. The CNAME now points at "nothing" on the
   provider — the name is unclaimed and reusable.
4. An attacker registers an account on that provider and claims the exact resource
   name the CNAME expects. The provider now serves the attacker's content under the
   victim's subdomain.

Variants:
- **CNAME dangle:** the classic case above (most common).
- **NXDOMAIN dangle:** CNAME target itself no longer resolves (Azure, Elastic
  Beanstalk, Discourse). Registering the resource recreates the hostname.
- **A/AAAA dangle:** a record points at a cloud IP from a pool (e.g. an old elastic IP
  or ephemeral cloud VM). Re-allocating that IP is racy and usually out of scope; treat
  cautiously.
- **NS dangle:** delegated nameservers for a zone are at a provider where the zone was
  deleted — claim the zone and you control the entire subtree. High impact, rarer.
- **MX / other:** dangling MX can enable mail interception in narrow cases.

---

## 2. Detection workflow

1. **Enumerate subdomains.**
   - `subfinder -d example.com -all -o subs.txt`
   - `amass enum -passive -d example.com`
   - Certificate Transparency: crt.sh, censys, and CT-backed sources.
2. **Resolve + capture CNAME chains.**
   - `dnsx -l subs.txt -cname -resp -o resolved.txt`
   - `dig +short CNAME sub.example.com` for spot checks.
   - Flag any record whose final target is a third-party provider domain.
3. **Probe the hosts.**
   - `httpx -l live.txt -status-code -title -web-server` to spot 404s / odd titles.
   - Fetch each candidate and capture the body for fingerprinting.
4. **Fingerprint.**
   - Match the body / status / NXDOMAIN signal against the matrix in section 4 or
     can-i-take-over-xyz.
   - `subjack -w subs.txt -t 100 -ssl -c fingerprints.json -v`
   - `nuclei -l live.txt -t http/takeovers/` (DNS + HTTP takeover templates).
5. **Verify claimability.** Confirm on the provider that the resource is genuinely
   unclaimed (signup/console check). A fingerprint alone is necessary, not sufficient —
   some services show the "not found" page but block re-claiming the domain
   (verification challenge), making takeover infeasible.

Tooling summary:
| Purpose | Tools |
|---|---|
| Subdomain enum | subfinder, amass, assetfinder, crt.sh |
| Resolution / CNAME | dnsx, dig, massdns, puredns |
| HTTP probe | httpx |
| Takeover detection | subjack, nuclei (http/takeovers), tko-subs, can-i-take-over-xyz |

---

## 3. Ethical proof (marker only)

The accepted standard from both HackerOne and can-i-take-over-xyz:
- Claim the resource **discreetly**.
- Serve a **harmless** HTML file on a **random/hidden path** (not the index page).
- Embed your researcher handle and the report ID in an **HTML comment**.
- Example marker body: `<!-- subdomain takeover PoC by <handle>, report <id>, harmless marker, no malicious content -->`

Do NOT:
- Deface the landing page ("HACKED BY ...").
- Serve credential forms, login clones, or any real phishing content.
- Capture real users' cookies/tokens/traffic.
- Archive the PoC on the Wayback Machine / web.archive.org (programs view this
  negatively and it leaves a lasting public artifact).
- Leave the claimed resource serving content longer than needed; release it after the
  report is triaged.

---

## 4. Per-service fingerprints & claim steps

Status from can-i-take-over-xyz. "Vulnerable" = generally claimable; "Edge case" =
claimable only under specific conditions (e.g. resource never verified / certain
account states); "Not vulnerable" = provider added ownership verification — fingerprint
useful for inventory but takeover infeasible.

### Cloud / object storage
| Service | Status | Fingerprint | Claim |
|---|---|---|---|
| AWS/S3 | Vulnerable | `The specified bucket does not exist` | Create an S3 bucket with the exact name in the CNAME, enable static website hosting, upload marker. |
| AWS/Elastic Beanstalk | Vulnerable | `NXDOMAIN` | Recreate an EB environment with the dangling CNAME label in the matching region. |
| Microsoft Azure (App Service, Traffic Manager, CloudApp, Blob, etc.) | Vulnerable | `NXDOMAIN` | Create the Azure resource reusing the exact `*.azurewebsites.net` / `*.cloudapp.net` / `*.trafficmanager.net` label. |
| Google Cloud Storage | Not vulnerable | — | Ownership verification required. |
| AWS Cloudfront | Not vulnerable | — | Alternate domain (CNAME) verification. |

### Static site / PaaS hosting
| Service | Status | Fingerprint | Claim |
|---|---|---|---|
| GitHub Pages | Edge case | `There isn't a GitHub Pages site here.` | Create a repo, add a `CNAME` file with the subdomain, enable Pages. Only works when the domain isn't already verified by another org. |
| Heroku | Edge case | `No such app` | Create a Heroku app and add the custom domain. Edge case due to domain-claim protections. |
| Netlify | Edge case | `Not Found - Request ID:` | Create a Netlify site and add the custom domain. |
| Surge.sh | Vulnerable | `project not found` | `surge` deploy to the exact domain. |
| Pantheon | Vulnerable | `404 error unknown site!` | Add the domain to a Pantheon site. |
| Cargo Collective | Vulnerable | `404 Not Found` | Claim site / set custom domain. |
| Strikingly | Vulnerable | `PAGE NOT FOUND.` | Add custom domain to a Strikingly site. |
| Read the Docs | Vulnerable | `The link you have followed or the URL that you entered does not exist.` | Add the domain to an RTD project. |
| Firebase | Not vulnerable | — | — |
| Squarespace | Not vulnerable | — | — |

### Docs / support / status / marketing SaaS
| Service | Status | Fingerprint | Claim |
|---|---|---|---|
| Readme.io | Vulnerable | `The creators of this project are still working on making everything perfect!` | Register the project subdomain. |
| Ghost | Vulnerable | `Site unavailable.` | Claim the Ghost(Pro) subdomain. |
| Help Scout | Vulnerable | `No settings were found for this company:` | Add the custom domain in Help Scout. |
| Help Juice | Vulnerable | `We could not find what you're looking for.` | Add the custom domain. |
| Uberflip | Vulnerable | `Non-hub domain, The URL you've accessed does not provide a hub.` | Configure hub custom domain. |
| Pingdom | Vulnerable | `Sorry, couldn't find the status page` | Claim the public status page subdomain. |
| Campaign Monitor | Vulnerable | `Trying to access your account?` | Add the domain in CM. |
| GetResponse | Vulnerable | `With GetResponse Landing Pages, lead generation has never been easier` | Claim landing-page domain. |
| Canny | Vulnerable | `Company Not Found` | Register the company subdomain. |
| Agile CRM | Vulnerable | `Sorry, this page is no longer available.` | Claim domain. |
| JetBrains YouTrack (InCloud) | Vulnerable | `is not a registered InCloud YouTrack` | Register the InCloud instance. |
| Statuspage | Not vulnerable | — | Ownership verification. |
| Zendesk | Not vulnerable | `Help Center Closed` | Host-mapping verification required. |
| HubSpot | Not vulnerable | — | — |
| Freshdesk / Desk | Not vulnerable | — | — |

### Source / package / misc
| Service | Status | Fingerprint | Claim |
|---|---|---|---|
| Bitbucket | Vulnerable | `Repository not found` | Create a repo and set up Bitbucket hosting for the domain. |
| Gemfury | Vulnerable | `404: This page could not be found.` | Claim. |
| Discourse | Vulnerable | `NXDOMAIN` | Recreate the Discourse-hosted instance. |
| Ngrok | Vulnerable | `Tunnel *.ngrok.io not found` | Claim the reserved domain/tunnel. |
| Short.io | Vulnerable | `Link does not exist` | Add the domain in Short.io. |
| Wordpress.com | Vulnerable | `Do you want to register *.wordpress.com?` | Register the blog subdomain. |
| HatenaBlog | Vulnerable | `404 Blog is not found` | Claim blog. |
| Uptime Robot | Vulnerable | `page not found` | Claim status page domain. |
| Shopify | Edge case | `Sorry, this shop is currently unavailable.` | Add custom domain to a shop (edge case — domain-connect protections). |
| Fastly | Not vulnerable | `Fastly error: unknown domain:` | Account-bound domain verification. |
| Akamai / Acquia / GitLab Pages / Mailchimp | Not vulnerable | — | — |

> Always re-check can-i-take-over-xyz for current status — providers add verification
> over time and statuses change. NXDOMAIN-class entries depend on the exact resource
> type and region.

---

## 5. Impact & chaining (the part that earns severity)

The dangling record is rarely the whole story. Determine what the parent app trusts
about the subdomain, then chain.

- **Cookie scoping / session hijack.** If the app sets cookies with
  `Domain=.example.com`, your controlled subdomain can read them (session theft) or
  write/overwrite them (session fixation, forcing a victim into an attacker-controlled
  session, or poisoning CSRF tokens). Check `Set-Cookie` domains on the main app.
- **OAuth `redirect_uri` abuse.** If the IdP/app allows the subdomain (explicitly or via
  a wildcard like `*.example.com`) as a redirect target, send victims through a real
  OAuth flow that lands on your subdomain and capture the authorization code/token.
  Pivot to `/oauth`.
- **CSP bypass.** If the subdomain appears in `script-src` / `style-src` /
  `connect-src` / `frame-src`, you can host script the main app's CSP trusts → stored-
  or reflected-XSS-equivalent execution in the main app's context. Pivot to `/cors`.
- **CORS allowlist abuse.** If the app reflects/whitelists the subdomain as an allowed
  `Origin` with `Access-Control-Allow-Credentials: true`, read authenticated
  cross-origin responses. Pivot to `/cors`.
- **SSO / embeds / postMessage.** Subdomain trusted as an embed parent/child or
  postMessage origin → message-passing abuse.
- **Phishing.** Even with no technical trust, a legitimate, valid-TLS host on the real
  domain is far more convincing for credential phishing (report as impact, do not
  actually run a phishing page).

Severity rubric: trusted-by-main-app subdomain (cookie/OAuth/CSP/CORS) = High/Critical;
user-facing but untrusted = Medium; isolated/unused with no trust = Low/Informational.

---

## 6. Prevention (for the report's remediation section)

- **Remove DNS records before/at decommission.** Tear down the DNS entry as part of the
  same change that deletes the cloud/SaaS resource.
- **Provision DNS last, deprovision DNS first** ("DNS-last" ordering): only create the
  CNAME after the resource exists; delete the CNAME before deleting the resource.
- **Periodic dangling-record audits.** Continuously resolve all subdomains and alert on
  CNAMEs pointing to unclaimed providers (the detection workflow above, run as a cron).
- **Prefer providers with domain-ownership verification** (DNS TXT challenge), and
  enable it where offered.
- **Avoid wildcard trust.** Don't use `*.example.com` in OAuth redirect allowlists, CSP,
  or CORS; scope cookies as tightly as possible (avoid broad `Domain=.example.com`).
- **Inventory third-party services** and tie each to an owner so teardown is tracked.

---

## 7. _EXPLOIT log template

```
# subdomain-takeover/<target-sub>.md
target:      docs.example.com
discovered:  recon-mapper phase 2 (CNAME inventory)
dns:         docs.example.com. 300 IN CNAME victim.github.io.
fingerprint: HTTP 404 body "There isn't a GitHub Pages site here."
claimable:   yes — no existing Pages verification on the domain
claim:       created repo <user>/poc, CNAME file = docs.example.com, Pages enabled
proof:       https://docs.example.com/poc-<handle>-<reportid>.html
proof_body:  <!-- subdomain takeover PoC by <handle>, report <id>, harmless marker -->
trust:       app sets Domain=.example.com session cookie -> chains to session hijack
chain_refs:  /oauth (redirect_uri allowlist), /cors (CSP script-src)
severity:    High (parent-domain cookie scope)
cleanup:     repo deleted / domain released after triage
```
