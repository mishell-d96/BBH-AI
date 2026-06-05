---
name: clickjacking
description: "Clickjacking / UI redress — frame a target and overlay invisible UI so a victim's clicks trigger a sensitive action. Use when a framable sensitive action exists AND X-Frame-Options / CSP frame-ancestors is missing. Not for missing-XFO alone with no impactful action."
---

# Clickjacking

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


UI-redress attack: load the target site in a transparent iframe stacked over a decoy, so the victim's real clicks land on a sensitive control. CSRF tokens do NOT help — the action runs in the victim's authenticated session.

## When to test
Only when ALL hold (otherwise it is noise):
1. The page can actually be framed (no X-Frame-Options, no CSP `frame-ancestors`).
2. The page contains a SENSITIVE, STATE-CHANGING action (delete account, change email/password, transfer funds, change 2FA, grant role, confirm purchase, revoke session).
3. That action is completable by CLICKS ALONE — no typing, no CAPTCHA, no re-auth prompt, no copy-paste of a value the attacker can't prefill.
4. The action is meaningful when triggered by an unwitting user (irreversible or hard to undo wins; toggles/UI prefs do not).

## Impact & priority
Be honest. Clickjacking is usually LOW and is one of the most-rejected junk classes.
- HIGH/MEDIUM only when a click lands a sensitive, hard-to-reverse action with a realistic UI-redress (e.g. one-click "Delete account", one-click "Change email to attacker@" via prefilled form, OAuth consent, confirm-money-transfer).
- LOW at best for anything reversible or low-value.
- Missing X-Frame-Options / frame-ancestors WITH NO impactful click-only action = NOISE. Do not report.
Escalate by chaining: prefilled GET form → email/password change → account takeover, or framing a DOM-XSS sink.

## Detection
1. Try to frame the sensitive page. Save a local HTML file with an `<iframe src="https://target/...">` and open it; if the page renders inside the frame, it is framable.
2. Check response headers on the sensitive endpoint:
   - `X-Frame-Options: DENY|SAMEORIGIN` → blocks framing (SAMEORIGIN still framable from same origin only).
   - `Content-Security-Policy: frame-ancestors 'none'|'self'|<allowlist>` → authoritative; takes precedence in modern browsers.
   - Both absent (or only a broken JS frame-buster) → candidate.
3. Confirm the action is click-only (inspect the form/flow). If it needs typed input, check whether the value can be prefilled via GET params.

## Exploitation
- **CSS overlay decoy**: position the target iframe at near-zero opacity above an enticing decoy ("Click to claim", "Play"), aligned so the decoy button sits exactly over the sensitive control (`z-index`, `position`, `opacity: 0.0001`).
- **Prefilled form**: if the form prepopulates from GET params, set attacker values in the iframe `src` (e.g. `?email=attacker@evil.com`); the victim only clicks the transparent submit.
- **Combine with DOM XSS**: frame a DOM-XSS URL; the unwitting click fires the payload in the target origin.
- **Multistep**: stack/sequence multiple decoys+iframes (e.g. add-to-basket then checkout); align and time each click.

## Common defenses & bypasses
- JS frame busters (top-vs-self checks) can be defeated with `sandbox="allow-forms allow-scripts"` (omit `allow-top-navigation`) so the frame can't navigate the top window. See `reference.md`.
- `X-Frame-Options: allow-from` is unsupported in Chrome 76+/Safari 12 — rely on CSP `frame-ancestors`.
- CSP `frame-ancestors` is the real gate; if present and restrictive, the target is NOT exploitable — drop it.

## Minimal PoC (for ./_EXPLOIT/)
Concrete overlay against a one-click sensitive action. Adjust offsets so the decoy button aligns over the real control.

```html
<!doctype html>
<!-- PoC: clickjacking on https://TARGET/account/delete (one-click, no XFO/frame-ancestors) -->
<html><head><style>
  iframe#target {
    position: absolute; top: 0; left: 0;
    width: 800px; height: 600px;
    opacity: 0.0001;            /* invisible but clickable */
    z-index: 2;
  }
  #decoy {
    position: absolute; z-index: 1;
    /* place button under the real "Delete account" control */
    top: 410px; left: 300px;
    padding: 14px 28px; font: 18px sans-serif;
  }
</style></head><body>
  <button id="decoy">Click to claim your reward</button>
  <iframe id="target"
          src="https://TARGET/account/delete"
          sandbox="allow-forms allow-scripts allow-same-origin"></iframe>
</body></html>
```
Prefilled-form variant: `src="https://TARGET/account/change-email?email=attacker@evil.com"`.
Log a screenshot/recording showing the click triggered the real action, plus the missing-header evidence, to `./_EXPLOIT/`.

## Don't report as noise
- Missing `X-Frame-Options` / `frame-ancestors` on a page with NO sensitive, click-completable action.
- Logout-only or read-only / informational pages.
- Actions requiring typing, CAPTCHA, re-auth, or a value the attacker cannot prefill.
- "Framable login page" with no follow-on impact.
You MUST demonstrate a concrete impactful action being triggered by a click — programs reject header-only findings.

## Deep reference
See `reference.md` and https://portswigger.net/web-security/clickjacking
