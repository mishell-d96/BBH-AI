---
name: host-header
description: "HTTP Host header attacks -> ATO via password-reset poisoning, routing-based SSRF, web cache poisoning, Host-based auth bypass. Use when the app trusts Host: reset/email links, vhosts, cache keys, proxy routing, absolute URLs. Signals: X-Forwarded-Host, duplicate Host, absolute request line."
---

# Host Header Attacks

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Attacks that abuse the client-controlled `Host` header (and override headers like `X-Forwarded-Host`) when an application or its infrastructure trusts it for links, routing, caching, or access control.

## When to test
Test anywhere the app derives a value from the Host header:
- **Password reset / account flows** — reset and confirmation links built from Host and emailed to the victim.
- **Other links in emails / responses** — invites, verification, magic links.
- **Caching layers** — CDN/cache that may store a Host-derived response.
- **Reverse proxy / load balancer routing** — front-end forwards based on Host.
- **Access control** — endpoints gated on "internal" Host/host-based trust.
- **Virtual hosting** — one server, many sites; internal vhosts not in public DNS.

## Impact & priority (honest)
- **High signal:** password reset poisoning → account takeover; routing-based SSRF reaching internal/cloud-metadata services; auth bypass to admin functionality; cache poisoning that serves an attacker payload to other users.
- **Medium:** virtual host discovery exposing a sensitive internal app.
- **Noise — do NOT report:** Host reflected into the response body with no sink and no security consequence. Self-only "poisoning" you cannot deliver to a victim. A reset link that uses Host but the token email is never reflected/sent to the attacker.

Lead with a working end-to-end chain, not the mere fact that Host is reflected.

## Detection
1. Send the request with a modified `Host:` value (e.g. `Host: attacker-controlled.example`). Does the app still respond 200? Where does the value surface — body, redirect `Location`, email link, an outbound request?
2. Add an override header alongside the real Host: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`. See if it overrides link/route generation.
3. Inject a **duplicate Host** header (two `Host:` lines) — front-end and back-end may disagree on which wins.
4. Try an **absolute URL** in the request line (`GET https://attacker.example/ HTTP/1.1` with a separate `Host:`) — some parsers prefer one source over the other.
5. Classify the sink: link in email (→ reset poisoning), cached (→ cache poisoning), routed upstream (→ SSRF), trusted for access (→ auth bypass), reflected only (→ likely noise).

## Exploitation
- **Password reset poisoning:** request a reset for the victim's account with your Host/`X-Forwarded-Host`. If the emailed link uses that host, the victim's click (or a token leaked via Referer/an image load to your host) yields the reset token → ATO. Strongest when the token reaches your server without victim interaction.
- **Web cache poisoning:** if a Host-derived value is reflected and the response is cached on a key you can also trigger as a victim, poison once and it serves to other users.
- **Auth bypass:** spoof an "internal" Host (or `X-Forwarded-Host`) to reach functionality gated on host-based trust (admin panels, internal-only routes).
- **Virtual host brute-force / internal vhosts:** keep the connection to the public IP, vary `Host:` across candidate internal names (intranet, admin, staging) to reach sites with no public DNS.
- **Routing-based SSRF:** if the front-end routes by Host, set `Host:` to a Collaborator/OAST domain (confirm the DNS/HTTP hit), then to internal IPs (169.254.169.254 metadata, 127.0.0.1, RFC1918 ranges).
- **SSRF via malformed request line:** when a proxy builds the upstream URL by prepending its backend, `GET @internal-host/ HTTP/1.1` can become `http://backend@internal-host/`, redirecting upstream.
- **Connection-state attacks:** if Host is validated only on the first request of a reused keep-alive connection, send a benign first request then a malicious second on the same connection to bypass routing/cache checks.

## Common bypasses (when validation rejects arbitrary Host)
- Override headers: `X-Forwarded-Host: evil.example` (often honored by default).
- Duplicate `Host:` headers; absolute URL in the request line vs. Host line discrepancy.
- Port injection: `Host: legit.example:malicious-payload`.
- Line wrapping / leading space-indented header continuation that one parser folds and another ignores.

## Minimal PoC (for ./_EXPLOIT/)
Safe, non-destructive — proves the reset link is built from a client-controlled host:
```bash
# Password reset poisoning probe — victim is YOUR test account; OAST host is yours.
curl -sk https://TARGET/forgot-password \
  -H 'Host: OAST_ID.oast.example' \
  --data 'email=your-test-account@example.com' -i

# Variant via override header if Host is validated:
curl -sk https://TARGET/forgot-password \
  -H 'Host: TARGET' -H 'X-Forwarded-Host: OAST_ID.oast.example' \
  --data 'email=your-test-account@example.com' -i
```
Proof = the reset email's link points to your OAST host, and/or your OAST receives the token. Log request, email link, and token receipt to `./_EXPLOIT/`.

## Don't report as noise
Host (or `X-Forwarded-Host`) merely echoed into the HTML/body with no cached delivery to a victim, no link/email sink, no routing effect, and no access-control bypass. Reflection alone is not impact.

## Deep reference
See `reference.md` for override-method details, each vector in depth, and prevention.
Sources: https://portswigger.net/web-security/host-header and https://portswigger.net/web-security/host-header/exploiting
