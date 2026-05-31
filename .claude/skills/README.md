# Bug-Bounty Skill Library

Web vulnerability testing-methodology skills for this workspace. Each skill is **auto-discovered**
and **slash-invocable** (e.g. `/sql-injection`) and also auto-triggers from its `description` when a
task matches. Methodology is grounded in the [PortSwigger Web Security Academy](https://portswigger.net/web-security).

Every skill follows the workspace doctrine in `../../CLAUDE.md`: impact-first, anti-noise, strict
scope gate, minimal **safe** PoC, log proven exploits to `../../_EXPLOIT/`.

## Structure of each skill
- `SKILL.md` — lean playbook: when to test, impact/priority, detection, exploitation, minimal PoC,
  and an explicit **"Don't report as noise"** section. Loads on trigger.
- `reference.md` — full PortSwigger-derived methodology (variants, bypass tables, prevention). Loads on demand.
- `cheatsheet.md` — copy-paste payload tables (payload-heavy classes only).

## Typical flow (map-first)
**`/recon-mapper`** (full map → happy-flow baselines → impact-scored candidates → skill routing) →
the routed vuln-class skill(s), tested highest-impact-first and chained → `/reporting` (write up a
validated finding). Vuln-class skills run **downstream** of `recon-mapper` and consume its artifacts;
don't engage them cold. Use `/recon` only for a quick, shallow sketch.

---

## Orchestration & cross-cutting
| Skill | Use for |
|-------|---------|
| [recon-mapper](recon-mapper/) | **Map-first orchestrator** — full surface map → happy-flow baselines → impact-scored candidates → routing to the skills below (run this first) |
| [recon](recon/) | Quick, shallow attack-surface sketch (subdomains/content/params/tech) when you don't need the full pipeline |
| [essential-skills](essential-skills/) | Payload encoding/obfuscation for filter/WAF bypass; scanner-assisted manual testing |
| [reporting](reporting/) | Turning a validated finding into a clear, impact-led, reproducible report |

## Server-side
| Skill | Use for |
|-------|---------|
| [sql-injection](sql-injection/) | SQLi — UNION, blind, error/time-based, DB enumeration *(+ cheatsheet)* |
| [nosql-injection](nosql-injection/) | MongoDB-style syntax & operator injection ($ne/$gt/$regex/$where) |
| [xxe-injection](xxe-injection/) | XML external entities — file read, SSRF, blind OOB |
| [os-command-injection](os-command-injection/) | Shell command injection → RCE (in-band & blind/OAST) |
| [ssti](ssti/) | Server-side template injection → RCE per engine *(+ cheatsheet)* |
| [path-traversal](path-traversal/) | Directory traversal / arbitrary file read *(+ cheatsheet)* |
| [ssrf](ssrf/) | Server-side request forgery — internal services, cloud metadata, blind |
| [access-control-idor](access-control-idor/) | Broken access control, IDOR, privilege escalation *(highest-ROI class)* |
| [authentication](authentication/) | Login/2FA/reset flaws → account takeover |
| [file-upload](file-upload/) | Upload flaws → web-shell RCE, stored XSS via SVG/HTML |
| [business-logic](business-logic/) | Logic flaws — price/quantity tampering, flawed assumptions |
| [race-conditions](race-conditions/) | TOCTOU / limit-overrun / double-spend (single-packet attack) |
| [information-disclosure](information-disclosure/) | Leaked secrets/source/PII (strict anti-noise) |
| [request-smuggling](request-smuggling/) | HTTP desync (CL.TE/TE.CL/TE.TE/H2 downgrade/CL.0) |
| [host-header](host-header/) | Host header attacks — reset poisoning, routing-based SSRF |
| [web-cache-poisoning](web-cache-poisoning/) | Poisoning cached responses via unkeyed inputs |
| [web-cache-deception](web-cache-deception/) | Caching other users' authenticated responses |

## Client-side
| Skill | Use for |
|-------|---------|
| [xss](xss/) | Reflected/stored/DOM XSS, context breakouts, CSP-aware *(+ cheatsheet)* |
| [csrf](csrf/) | Cross-site request forgery, token & SameSite bypasses |
| [dom-based](dom-based/) | DOM XSS & other client-side sink vulns (taint-flow) |
| [cors](cors/) | CORS misconfig → cross-origin data theft (strict anti-noise) |
| [clickjacking](clickjacking/) | UI redress on sensitive actions (strict anti-noise) |
| [websockets](websockets/) | CSWSH and injection over WebSockets |
| [open-redirect](open-redirect/) | Open redirects — low alone, force-multiplier (→ OAuth/SSRF/CSP) |

## Authentication & advanced
| Skill | Use for |
|-------|---------|
| [oauth](oauth/) | OAuth 2.0 / OIDC flaws → account takeover |
| [jwt](jwt/) | JWT signature/alg-confusion/header-injection attacks |
| [saml-sso](saml-sso/) | SAML/SSO XML signature wrapping → auth bypass / ATO |
| [deserialization](deserialization/) | Insecure deserialization → RCE (gadget chains) |

## Emerging / specialized
| Skill | Use for |
|-------|---------|
| [prototype-pollution](prototype-pollution/) | Client-side DOM XSS & server-side RCE via `__proto__` |
| [graphql](graphql/) | GraphQL IDOR, introspection, alias/batch abuse, CSRF |
| [web-llm-attacks](web-llm-attacks/) | Prompt injection, excessive agency, insecure output handling |
| [api-testing](api-testing/) | REST/API recon, mass assignment, parameter pollution |

## Recon-driven & supply-chain
*(typically surfaced by `/recon-mapper`'s asset inventory)*
| Skill | Use for |
|-------|---------|
| [subdomain-takeover](subdomain-takeover/) | Dangling DNS → claim unclaimed service on a trusted subdomain |
| [secrets-exposure](secrets-exposure/) | Live keys/tokens in JS bundles, source maps, `.git`, repos |
| [cloud-storage-misconfig](cloud-storage-misconfig/) | Public/writable S3/GCS/Azure buckets & bucket takeover |
| [dependency-confusion](dependency-confusion/) | Unclaimed internal package names → supply-chain RCE in CI |
