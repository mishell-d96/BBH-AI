# OAuth 2.0 / OpenID Connect — Deep Reference

Sources:
- https://portswigger.net/web-security/oauth
- https://portswigger.net/web-security/oauth/openid
- https://portswigger.net/web-security/oauth/preventing

OAuth is an **authorization** framework that apps repurpose for **authentication** ("log in
with X"). The mismatch between what OAuth guarantees and what apps assume is the root of most
of these bugs.

---

## 1. Roles
- **Client application** — the site/app that wants access to user data (the "relying party").
- **Resource owner** — the user whose data/identity is involved.
- **OAuth service provider** — controls the data and issues tokens. Split into:
  - **Authorization server** — `/authorize` (front-channel) and `/token` (back-channel).
  - **Resource server** — APIs that accept the access token, e.g. `/userinfo`.

Recon endpoints (JSON config dump of all endpoints/features supported):
- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`

Common parameters: `client_id`, `client_secret`, `redirect_uri`, `response_type`, `scope`,
`state`, `code`, `access_token`, `id_token`, `grant_type`, `nonce` (OIDC), `request_uri` (OIDC).

---

## 2. Grant types

### Authorization code grant
1. Client sends user to `/authorize` with `client_id`, `redirect_uri`, `response_type=code`,
   `scope`, `state`.
2. User authenticates and consents.
3. Authorization server redirects back to `redirect_uri` with `?code=...&state=...`.
4. Client (back-channel, server-to-server) POSTs to `/token` with `code`, `client_id`,
   `client_secret`, `redirect_uri` and receives `access_token` (+ `id_token` for OIDC).
5. Client calls resource server (`/userinfo`) with the access token.

The token never traverses the browser, so it's the more secure flow. The **code** still passes
through the browser, so leaking it (plus an active victim session at the client) can be enough.

### Implicit grant
1. `/authorize` with `response_type=token` (or `id_token token`).
2. Server redirects back with the **access token in the URL fragment**:
   `https://client/callback#access_token=...&token_type=Bearer&...`.
3. Client JS reads the fragment and typically POSTs the token (and user fields) to its own
   backend to establish a session.

No back-channel, no `client_secret`. The token is exposed to the browser, browser history,
`Referer`, and any JS on the page. Mainly used by SPAs; weaker and error-prone. (Modern best
practice is auth code + PKCE instead.)

---

## 3. Client-side vulnerabilities

### Improper implicit-grant handling
After the implicit flow, clients often POST something like
`{ "email": "...", "username": "...", "token": "<access_token>" }` to their backend to log the
user in. If the backend **trusts the submitted user fields instead of deriving identity from the
token**, an attacker submits a valid (own) token with the **victim's email/username** and is
logged in as the victim. Always test: can I change the identity fields while keeping my token?

### Flawed CSRF protection / missing `state`
`state` should be an unguessable value bound to the user's session (acts as a CSRF token on the
callback). If `state` is **absent, static, guessable, or not validated**, the callback is
CSRF-able. Classic exploit — **forced account linking**:
1. Attacker logs into the client (own account #1), starts "link <provider>", and captures the
   provider callback URL containing the attacker's `code`.
2. Attacker strips/ignores `state` and delivers that callback URL to a logged-in victim.
3. Victim's browser hits the callback -> the victim's client account is now linked to the
   attacker's social identity.
4. Attacker clicks "Login with <provider>" -> authenticated as the victim.

Note: "no `state` on a pure login that just re-authenticates and performs no stateful change"
is usually **not** reportable — there must be a sensitive action (linking, state change) to
exploit. See SKILL.md "Don't report as noise".

---

## 4. Service-side (provider) vulnerabilities

### Leaking authorization code / token via redirect_uri
If `redirect_uri` isn't strictly validated, an attacker crafts an `/authorize` URL pointing the
`code`/`token` at an attacker-controlled location and sends it to a logged-in victim. For the
**auth code** flow, the attacker does **not** need `client_secret` or the resulting token if the
victim has an active client session — the leaked code can be redeemed/replayed at the client.

When external hosts are blocked, leak via a page on the **whitelisted** domain that exposes the
URL — open redirect, XSS, reflected JS handling the fragment, or HTML injection (an `<img>` tag
sending the full URL in the `Referer` header).

### Flawed scope validation
- **Auth code flow:** a malicious registered client adds extra `scope` at the `/token` exchange:
  ```
  POST /token
  client_id=...&client_secret=...&code=...&scope=openid%20email%20profile%20admin
  ```
  If the server doesn't check the requested scope against what the user originally consented to,
  the issued token is over-privileged.
- **Implicit flow:** attacker holding a token adds `scope` directly on `/userinfo` (or other
  resource) requests. If unvalidated, extra data is returned.

### Unverified user registration -> ATO
Some providers let you register/use an account **without verifying email ownership**. Attacker
registers a provider account with the **victim's email**; when the client maps provider identity
to its own account **by email**, the attacker logs into the victim's client account. Also the
mirror: a client that trusts an unverified `email` claim from the provider.

### Access-token misbinding
Resource server must verify the token was issued **to the requesting `client_id`** and that the
**scope matches what was granted**. Missing these checks enables token reuse/confused-deputy ATO.

---

## 5. redirect_uri attack matrix
Providers should require a registered whitelist and do **strict byte-for-byte** comparison.
Weak/pattern matching is bypassable:

| Technique | Example |
|---|---|
| Appended path | `https://allowed.com/anything` |
| Appended query/params | `https://allowed.com/callback?x=1` |
| Path traversal to leaky page | `https://allowed.com/oauth/callback/../../example/path` |
| Subdomain / suffix | `https://allowed.com.evil.net`, `https://allowedXcom.evil.net` |
| Prefix in path | `https://evil.net/allowed.com` |
| Userinfo `@` trick | `https://allowed.com@evil.net`, `https://evil.net\@allowed.com` |
| Parser-confusion mix | `https://allowed.com &@foo.evil.net#@bar.evil.net/` |
| Fragment / `#` games | `https://allowed.com#@evil.net`, `...#.evil.net` |
| `localhost` special-casing | `localhost.evil.net` when `localhost` is trusted |
| Parameter pollution (HPP) | two `redirect_uri` params; server validates one, uses the other |
| Open-redirect chaining | `redirect_uri=https://allowed.com/redirect?to=https://evil.net` |
| Backslash / encoding | `https://allowed.com\.evil.net`, double/CR-LF/Unicode-encoded hosts |

Goal of all of these: land the `code`/`token` somewhere the attacker reads it (own host,
`Referer`, open redirect, or leaky in-scope page).

---

## 6. OpenID Connect (OIDC) specifics
OIDC adds an **identity/authentication layer** on top of OAuth.

- **`id_token`** — a JWT (signed with JWS) containing **claims** about the user
  (`sub`, `email`, `family_name`, `iat`, `auth_time`, `nonce`, ...). The client gets identity
  data directly, no extra round trip.
- **Standardized scopes** (vs OAuth's provider-specific ones): `openid` (mandatory), `profile`,
  `email`, `address`, `phone`.
- **`response_type`** may include `id_token`. **`nonce`** binds the `id_token` to the request
  (replay defense — analogous role to `state`).

Identify OIDC: look for the `openid` scope in `/authorize`, check
`/.well-known/openid-configuration`, or probe by adding `scope=openid` / `response_type=id_token`.

OIDC-specific vulns:
- **Unprotected dynamic client registration** — if the registration endpoint needs no auth,
  attackers POST attacker-controlled metadata. URIs in the registration (`jwks_uri`, `logo_uri`,
  `sector_identifier_uri`, etc.) that the server fetches without validation give **second-order
  SSRF**.
- **Authorization requests by reference (`request_uri`)** — the provider accepts a `request_uri`
  pointing to a JWT holding the OAuth params, then fetches it. Two attacks:
  - **SSRF** — point `request_uri` at internal resources.
  - **Validation bypass** — query-string validation (e.g. of `redirect_uri`) may not apply to
    params embedded inside the referenced JWT.
- **id_token validation flaws** — `alg=none`, unverified signature, missing `nonce`/`aud`/`iss`
  checks let a forged/replayed `id_token` authenticate the attacker.

OIDC's stricter spec reduces some quirks, but it remains exposed to all OAuth attacks above plus
these.

---

## 7. Prevention

**OAuth service providers**
- Require a **registered whitelist** of `redirect_uris`; **strict byte-for-byte** comparison
  (no pattern/prefix matching).
- Enforce `state` carrying session-specific data (e.g. a hash of the session cookie).
- On the resource server, verify the access token was issued to the requesting `client_id` and
  that the **requested scope == granted scope**.
- Authenticate dynamic client registration; validate/deny SSRF-prone URIs and `request_uri`.

**Client applications**
- Always send `state` (even though the spec doesn't mandate it); validate it on callback.
- Send `redirect_uri` to **both** `/authorize` and `/token` for consistent validation.
- Use **PKCE (RFC 7636)** for mobile/desktop/SPA clients that can't keep `client_secret` secret.
- Properly validate OIDC `id_token` per JWS/JWE (signature, `iss`, `aud`, `exp`, `nonce`).
- Prevent `code`/token leakage via `Referer` when loading external resources; never put codes
  in dynamically generated JS.
- Derive user identity from the **token/claims**, never from client-submitted form fields.
