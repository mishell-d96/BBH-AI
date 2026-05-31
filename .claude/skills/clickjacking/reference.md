# Clickjacking — Deep Reference

Source: https://portswigger.net/web-security/clickjacking

Clickjacking (UI redress) tricks a user into clicking actionable content on a hidden page they didn't intend to interact with. The target page is loaded in a transparent iframe overlaid on a decoy. Unlike CSRF, it requires a real user click — and because the click happens in the target's authenticated session, **CSRF tokens do not prevent clickjacking**.

---

## 1. Impact bar for reporting (read first)

Clickjacking is a top junk-report class. A valid report MUST prove:
- The sensitive page is **framable** (no `X-Frame-Options`, no CSP `frame-ancestors`, or only a bypassable JS frame buster), AND
- A **sensitive state-changing action** (delete account, change email/password, change 2FA, money transfer, OAuth/permission grant, revoke session, confirm purchase) is **completable by clicks alone**, AND
- A realistic UI-redress aligns a decoy control over the real one.

Reject / do not report:
- Missing security header on a page with no click-only impactful action.
- Reversible toggles, UI preferences, logout, read-only pages.
- Actions needing typed input the attacker can't prefill, CAPTCHA, or re-authentication.

Severity guidance: account takeover via prefilled email/password change or one-click delete-account ≈ Medium (sometimes High with full ATO chain); reversible/low-value ≈ Low or N/A.

---

## 2. Basic attack construction (CSS overlay)

Stack a near-invisible target iframe above a decoy using `position`, `z-index`, and tiny `opacity`. Align the decoy button so it sits exactly over the sensitive control.

```html
<head>
<style>
  #target_website {
    position: relative;
    width: 128px;
    height: 128px;
    opacity: 0.00001;   /* invisible, still clickable; sits below browser transparency-detection thresholds */
    z-index: 2;
  }
  #decoy_website {
    position: absolute;
    width: 300px;
    height: 400px;
    z-index: 1;
  }
</style>
</head>
<body>
  <div id="decoy_website">...decoy content designed to make the user click...</div>
  <iframe id="target_website" src="https://vulnerable-website.com"></iframe>
</body>
```

Tuning the alignment: measure the pixel position of the real action button inside the iframe (resize the iframe and temporarily raise opacity to 1 while developing), then place the decoy element at the same coordinates. Set opacity back to ~0.0001 for delivery.

---

## 3. Prefilled-form clickjacking

If a form prepopulates its fields from GET parameters, the attacker supplies malicious values directly in the iframe `src`. The victim only clicks the (transparent) submit button.

```html
<iframe id="target_website"
        src="https://vulnerable-website.com/email/change?email=attacker@evil.com">
</iframe>
```

This converts a click into a meaningful attack (e.g. email change → password-reset → account takeover) without any typing by the victim. Test which fields are prefillable via query string; partial prefill plus a single click is often enough.

---

## 4. Frame buster scripts & bypasses

Legacy client-side protections ("frame busters") typically:
- check the current window is the top window (`top === self`),
- verify all frames are visible / block clicks on invisible frames,
- flag suspected attacks to the user, or navigate the top window away.

Bypass with the HTML5 iframe `sandbox` attribute. Using `allow-forms` and/or `allow-scripts` **without** `allow-top-navigation` lets the framed page run forms/scripts but prevents it from navigating or inspecting the top-level window, neutralizing the buster:

```html
<iframe id="victim_website"
        src="https://victim-website.com"
        sandbox="allow-forms"></iframe>
```

Notes:
- Add `allow-scripts` only if the page needs JS to function; some busters rely on script so test both.
- Frame busters are not a real defense — `X-Frame-Options` / CSP `frame-ancestors` are. If only a JS buster exists, the page is still likely exploitable.

---

## 5. Combining clickjacking with DOM XSS

When a DOM-based XSS sink exists, frame the XSS-triggering URL. The unwitting click fires the payload in the target origin (with the victim's session):

```html
<iframe id="target_website"
        src="https://vulnerable-website.com/#payload-that-hits-dom-xss-sink">
</iframe>
```

This upgrades a "needs user interaction" DOM XSS into a fully delivered exploit and raises impact considerably.

---

## 6. Multistep clickjacking

Actions requiring more than one interaction (e.g. add to basket → proceed to checkout → confirm) need multiple overlays/iframes coordinated so each decoy click maps to the correct control in sequence. Carefully manage timing and the z-index/position of each layer; the user performs a believable multi-click decoy flow (e.g. a short "game") while each click advances the hidden multistep action.

---

## 7. Prevention (and what kills your finding)

### X-Frame-Options (response header)
- `X-Frame-Options: deny` — never framable.
- `X-Frame-Options: sameorigin` — framable only from same origin.
- `X-Frame-Options: allow-from https://example.com` — allowlist a domain, but **unsupported in Chrome 76+ and Safari 12** — do not rely on it.

### Content-Security-Policy `frame-ancestors` (authoritative)
Stronger and more consistent than XFO; takes precedence in modern browsers.
- `Content-Security-Policy: frame-ancestors 'none';` — no framing (≈ XFO deny).
- `Content-Security-Policy: frame-ancestors 'self';` — same origin only.
- `Content-Security-Policy: frame-ancestors example.com;` — allowlist specific origins.

If a restrictive `frame-ancestors` is present, the page is NOT clickjackable — drop the candidate regardless of XFO.

### SameSite cookies (partial, indirect)
`SameSite=Lax`/`Strict` on session cookies can break cross-site framed actions because the framed request is cross-site, so the session cookie may not be sent — sometimes neutralizing the attack. It is a CSRF-oriented control, not a designed clickjacking defense; treat it as a confounder when a frameable page still doesn't complete the action.

---

## 8. Reporting checklist

- [ ] Sensitive, irreversible/high-value, click-only action identified.
- [ ] Verified framable: headers captured (XFO + CSP frame-ancestors absent or non-restrictive).
- [ ] Working PoC HTML with aligned decoy over the real control.
- [ ] Evidence the click triggered the real action (screen recording / screenshot + resulting state change).
- [ ] Honest severity, account for SameSite and any JS buster bypass used.
- [ ] PoC + evidence stored under `./_EXPLOIT/`.
