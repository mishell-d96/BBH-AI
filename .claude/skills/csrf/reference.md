# CSRF — Deep Reference

Cross-Site Request Forgery: an attacker-hosted page causes a victim's browser to
send an authenticated, state-changing request to a target the victim is logged
into. The browser automatically attaches the victim's cookies; the server cannot
distinguish the forged request from a genuine one unless it has an
unpredictable, session-bound anti-CSRF defence.

Primary sources:
- https://portswigger.net/web-security/csrf
- https://portswigger.net/web-security/csrf/bypassing-token-validation
- https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
- https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses

---

## 1. Conditions for CSRF
All three must be true:
1. **A relevant action** — something worth forging (change email/password, transfer
   funds, change settings, escalate privilege).
2. **Cookie-based session handling** — the app identifies the user solely via
   session cookies that the browser sends automatically. (If auth requires a
   bearer token in a custom header that JS must set, cross-site requests can't
   add it — generally not CSRF-able.)
3. **No unpredictable request parameters** — the attacker can determine/guess all
   values needed. An unguessable, session-bound CSRF token in the body breaks
   this condition (unless one of the bypasses below applies).

## 2. Building the exploit

### POST — auto-submitting form
```html
<html>
 <body>
  <form action="https://vulnerable-website.com/email/change" method="POST">
   <input type="hidden" name="email" value="pwned@evil-user.net" />
  </form>
  <script>
   document.forms[0].submit();
  </script>
 </body>
</html>
```
The form auto-submits on page load; the victim's session cookie is attached.

### GET — single tag, no script needed
```html
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">
```
Works whenever the sensitive action is reachable by GET.

### Notes
- Use `enctype` / hidden inputs to reproduce the exact body the server expects.
- For JSON-only endpoints, CSRF is usually blocked because a cross-site
  `fetch` with `Content-Type: application/json` triggers a CORS preflight; only
  consider it if the endpoint also accepts `text/plain`/form encodings.

---

## 3. CSRF token validation flaws

### 3.1 Validation depends on request method
The token is checked for POST but not for GET (or other methods). Resend the
action as GET (some frameworks allow a `_method` override param to tunnel a
different method). No token needed.

### 3.2 Validation depends on token presence
The server validates the token only if the parameter is present; omit the
parameter entirely and validation is skipped.
```html
<form action="https://vulnerable-website.com/email/change" method="POST">
  <input type="hidden" name="email" value="pwned@evil-user.net" />
</form>
<script>document.forms[0].submit();</script>
```
(Note: no `csrf` field at all.)

### 3.3 Token not tied to the user session
The app keeps a global pool of valid tokens and accepts any of them regardless
of which user it was issued to. The attacker fetches a valid token from their
own session and hard-codes it into the exploit form for the victim.

### 3.4 Token tied to a non-session cookie
The token is validated against a separate cookie (e.g. `csrfKey`) that is NOT
the session cookie. If the app has any way to set that cookie (a cookie-setting
endpoint, a request whose param reflects into a `Set-Cookie`, response splitting,
etc.), the attacker:
1. Obtains a matching token + cookie pair from their own session.
2. Uses the cookie-setting vector to plant their `csrfKey` cookie in the victim.
3. Submits the form carrying their matching token.
The session cookie stays the victim's, so the action executes as the victim.

### 3.5 Token duplicated in a cookie (double-submit, broken)
The server merely checks that the token in the request body equals the token in
a cookie — without any server-side state. The attacker invents an arbitrary
token, plants it as the cookie via a cookie-setting vector, and submits the same
value in the body. The two match, so the check passes.

---

## 4. SameSite cookie restrictions and bypasses

### 4.1 Levels
- **Strict** — cookie never sent on any cross-site request. Strong; defeat needs
  an on-site gadget or sibling-domain vector.
- **Lax** — cookie sent on cross-site requests only when both (a) it's a
  top-level navigation (URL bar changes) and (b) the method is "safe" (GET).
  Chrome treats cookies without an explicit `SameSite` attribute as Lax-by-default.
- **None** — no SameSite restriction (must also be `Secure`). Fully CSRF-able.

"Same-site" is determined by the registrable domain (eTLD+1), not the origin —
so `a.target.com` and `b.target.com` are same-site though cross-origin.

### 4.2 Bypass: Lax + GET-accepting endpoint
If the sensitive action accepts GET, trigger a top-level navigation so the Lax
cookie is sent:
```html
<script>
  document.location = 'https://target.com/account/transfer?to=attacker&amount=1000000';
</script>
```
Method-override params (e.g. Symfony `_method=POST` on a GET) can let a GET
top-level navigation perform a "POST" action.

### 4.3 Bypass: on-site gadgets (defeats Strict)
A client-side redirect (DOM-based open redirect, JS navigation) is not a real
HTTP redirect — the final request is a fresh, same-site request and carries even
Strict cookies. Chain: attacker page → navigate to an on-site gadget that
redirects to the sensitive action with attacker-controlled params.

### 4.4 Bypass: sibling / related domains
If any sibling host within the same site (same eTLD+1) has XSS or a CSRF-able
endpoint, requests issued from it are same-site and carry the cookie. Compromise
the weaker sibling to attack the protected host.

### 4.5 Bypass: newly-issued-cookie window
Chrome's Lax-by-default applies a grace period (~120 seconds) during which
top-level POST requests on freshly-set cookies are still sent cross-site. Force
the victim to obtain a fresh session cookie (e.g. trigger an OAuth/SSO
re-authentication, often via a popup opened from a user-gesture click handler),
then fire a top-level POST within the window.

---

## 5. Referer-based defences and bypasses

### 5.1 Validation depends on Referer presence
The app validates Referer only when present. Suppress it so validation is
skipped:
```html
<meta name="referrer" content="never">
```

### 5.2 Naive validation bypasses
- **Domain-prefix check** ("does Referer start with target?"): host the exploit
  on `https://vulnerable-website.com.attacker-website.com/...`.
- **Substring check** ("does the target domain appear anywhere?"): put it in the
  query string: `https://attacker-website.com/csrf?vulnerable-website.com`.
  Browsers strip query strings from Referer by default; counter with response
  header `Referrer-Policy: unsafe-url` so the full URL (with query) is sent.

---

## 6. Prevention (to recognise correct fixes / report nuance)
- **Synchronizer token pattern** — unpredictable, session-bound token validated
  server-side on every state-changing request. Strongest. Token must be tied to
  the session and required (not presence-optional, not method-scoped).
- **SameSite cookies** — `Strict` (or `Lax` for usability) as defence-in-depth.
  Lax alone leaves GET-based actions and the gadget/sibling vectors above.
- **Double-submit cookie** — only safe if signed/HMAC'd and the cookie cannot be
  overwritten by the attacker; otherwise see 3.5.
- **Custom-header requirement** (e.g. `X-Requested-With`) — relies on CORS
  preflight preventing cross-site addition of the header.
- Referer/Origin checks are weak alone (see section 5); use as defence-in-depth.

---

## 7. Reporting guidance (impact-first)
- **Report:** forgeable account-takeover actions (email/password/2FA change,
  recovery-email/phone change), forgeable financial/data-mutating actions.
- **Frame impact concretely:** e.g. "CSRF on email change → trigger password
  reset to attacker mailbox → full account takeover."
- **Do not report:** logout CSRF, trivial/non-sensitive actions, or actions fully
  mitigated by SameSite with no demonstrated bypass. "Missing token" without a
  proven exploitable state change is noise.
- PoC: minimal auto-submitting page using a benign attacker-controlled value;
  demonstrate then revert; never touch real victim data.
