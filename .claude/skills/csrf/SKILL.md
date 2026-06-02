---
name: csrf
description: "Cross-Site Request Forgery — force an authenticated victim's browser into state-changing requests. Use for POST/PUT/DELETE or sensitive GET actions with missing/weak anti-CSRF tokens, SameSite gaps, token not tied to session, method-only checks, or double-submit cookie."
---

# CSRF (Cross-Site Request Forgery)

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Force a logged-in victim's browser to send an authenticated, attacker-chosen state-changing request. Impact depends entirely on WHAT action can be forged.

## When to test
Any **state-changing** action that relies on the session cookie alone for authorization:
- Change email / password / phone / 2FA settings (account takeover relevant)
- Fund transfer, place order, change payout/shipping address
- Account settings, role/permission changes, API key creation
- Anything that mutates server state via a predictable request

Three conditions must hold (PortSwigger): (1) a relevant state-changing action, (2) cookie-based session handling, (3) all request parameters are attacker-predictable (no unknown token).

## Impact & priority (be honest)
- **High signal:** CSRF on account-takeover-relevant actions — change email then trigger password reset, change password directly, disable 2FA, add attacker email/phone. Report these.
- **Medium:** financial/data-mutating actions with real damage (transfer, change payout address).
- **Low / noise:** CSRF on trivial/non-sensitive actions, logout (logout CSRF is almost always noise), or any action fully mitigated by `SameSite=Lax`/`Strict` with no working bypass and no exploitable gadget. Do not report.

## Detection
1. Capture the target state-changing request. Note method, params, and which header/param carries any anti-CSRF token.
2. **Token presence:** remove the token param entirely — does the request still succeed?
3. **Token-method coupling:** switch POST→GET (or use `_method` override) — is the token still enforced?
4. **Token-session binding:** take YOUR valid token, replay it on the victim session — accepted? Then it isn't tied to the session.
5. **Double-submit:** is the token only compared against a value in a cookie (not server state)?
6. **SameSite:** inspect `Set-Cookie` for the session cookie. None/absent → testable cross-site. Lax → only top-level GET cross-site; look for GET-accepting endpoint or gadget. Strict → need an on-site gadget or sibling-domain vector.
7. **Referer check:** does removing/altering Referer bypass validation?

## Exploitation
Build a self-submitting page hosted off-site that fires the request with the victim's cookies attached.

POST (auto-submit form):
```html
<form action="https://target/email/change" method="POST">
  <input type="hidden" name="email" value="attacker@evil.test">
</form>
<script>document.forms[0].submit();</script>
```
GET action:
```html
<img src="https://target/email/change?email=attacker@evil.test">
```

Token validation flaws (test each — see reference.md):
- **Not validated when absent:** drop the token param entirely.
- **Validated only on POST:** resend as GET.
- **Not tied to session:** embed your own valid token in the form.
- **Tied to a non-session cookie / double-submit:** use a cookie-injection vector (e.g. a separate Set-Cookie endpoint) to plant your cookie, then submit a matching token.

SameSite bypasses (see reference.md):
- **Lax + GET:** route the action through a GET endpoint via top-level navigation (`document.location=...`).
- **On-site gadget:** chain a same-site open redirect / client-side nav so the final request is same-site (defeats Strict).
- **Sibling/related domain:** leverage XSS/CSRF on a sibling host within the same site.
- **Newly-issued-cookie window:** Chrome's ~120s Lax grace period after a fresh auth (e.g. forced OAuth re-login).

Referer bypasses: suppress with `<meta name="referrer" content="never">`; or satisfy naive checks via subdomain (`target.com.evil.test`) or query string (`evil.test/?target.com`, needs `Referrer-Policy: unsafe-url`).

## Common bypasses
Full catalogue with conditions and payloads in **reference.md**.

## Minimal PoC (for ./_EXPLOIT/)
Minimal, safe, single auto-submitting page that changes the victim's account email to an attacker-controlled address — proving account-takeover reachability. Log to `./_EXPLOIT/<target>/csrf-email-change.html`:
```html
<!DOCTYPE html>
<html>
<body>
<!-- CSRF PoC: changes victim email -> attacker controlled. Authorized testing only. -->
<form id="poc" action="https://TARGET/account/email/change" method="POST">
  <input type="hidden" name="email" value="attacker+poc@evil.test">
</form>
<script>document.getElementById('poc').submit();</script>
</body>
</html>
```
Demonstrate, then revert the change. Use a benign attacker-controlled email; never touch real victim data or chain to an actual takeover.

## Don't report as noise
- Logout CSRF and other non-sensitive/trivial actions.
- Actions fully protected by `SameSite=Lax`/`Strict` with no demonstrated bypass or gadget.
- "Missing CSRF token" with no proven exploitable impact (no state change actually forgeable).

## Deep reference
See **reference.md** in this folder. Sources:
- https://portswigger.net/web-security/csrf
- https://portswigger.net/web-security/csrf/bypassing-token-validation
- https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
- https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses
