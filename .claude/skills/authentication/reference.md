# Authentication Vulnerabilities — Deep Reference

Authentication verifies *who* a user is (vs. authorization, which controls *what* they can do). Vulns arise two ways: (1) **weak mechanisms** that don't resist brute-force, and (2) **logic flaws / poor implementation** that allow full bypass ("broken authentication"). Factors: knowledge (passwords, security questions), possession (phone, token), inherence (biometrics).

Workspace doctrine: prove impact, minimal safe PoC, log to `./_EXPLOIT/`. Brute-force / credential-testing ONLY where explicitly permitted and ONLY against test accounts you control. Respect rate limits and scope.

Primary sources:
- https://portswigger.net/web-security/authentication
- https://portswigger.net/web-security/authentication/password-based
- https://portswigger.net/web-security/authentication/multi-factor
- https://portswigger.net/web-security/authentication/other-mechanisms
- https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning

---

## 1. Password-based authentication

Ref: https://portswigger.net/web-security/authentication/password-based

### 1.1 Username enumeration
Identifying valid usernames by observable differences between valid/invalid input. Sources of leakage:
- **Status codes** — a different HTTP status for a valid username. Best practice is identical responses regardless of validity, so any divergence is a tell.
- **Error messages** — "Invalid username" vs "Invalid password". Differences can be a single, even invisible, character (trailing whitespace, punctuation). Diff responses byte-for-byte; compare lengths.
- **Response timing** — a valid username triggers extra processing (password hash verification) producing measurable latency. Amplify by submitting an extremely long password so the valid-username path spends much longer hashing; invalid usernames short-circuit and return fast.
- **Other surfaces** — registration ("username already taken"), forgot-password ("no account with that email"), and account-recovery flows often leak the same way.

Reportability: enumeration alone is usually **low/noise** unless it feeds a concrete ATO chain (e.g. valid usernames + flawed lockout + common-password spray).

### 1.2 Brute-forcing passwords
Real attacks exploit human password patterns, not random space. Users base passwords on memorable words and apply predictable transforms to meet policy: `mypassword` -> `Mypassword1!`. On forced rotation they make minimal changes: `Mypassword1!` -> `Mypassword2!`. Build wordlists from these patterns plus context (company name, year, season).

### 1.3 Flawed brute-force protection
Protections and their bypasses:
- **Per-account lockout (N failures):** spray a small set (3-5) of very common passwords across *many* usernames — each account stays under threshold; you only need one hit. Combine with enumerated username list.
- **Counter reset on success:** if the failed-attempt counter resets after any successful login, interleave a login to an attacker-controlled account every few guesses to keep the victim account unlocked.
- **IP-based rate limiting:** bypass by spoofing the apparent client IP via `X-Forwarded-For` (and similar headers) or by rotating source IPs/proxies (only where permitted).
- **Multiple guesses per request:** some endpoints accept an array/JSON list of passwords in one request, evading per-request counting.
- **Credential stuffing:** because lockout is per-account and you try only one (breached) password per username, lockout never trips. Effective against password reuse.

### 1.4 HTTP Basic authentication
`Authorization: Basic base64(username:password)` is sent on every request:
- Credentials exposed on every request; dangerous without HSTS (downgrade/sniffing).
- Typically **no brute-force protection** and **no CSRF protection**.
- Credentials are often reused on more sensitive systems.
- Stateless: doesn't integrate with session-management protections, so session-based defenses don't apply.

---

## 2. Multi-factor authentication (MFA / 2FA)

Ref: https://portswigger.net/web-security/authentication/multi-factor

### 2.1 Bypassing 2FA entirely
If the app loads authenticated pages without verifying the second step completed, you can skip it. After completing step 1 (password) you receive a "logged-in" session; try browsing directly to a post-login page (e.g. `/my-account`). If it loads, the verification gate is decorative.

### 2.2 Flawed 2FA logic
The verification step must be bound to the *same* user/session that passed step 1. Broken pattern — the verify request carries a user identifier the attacker controls:
```
POST /login-steps/second HTTP/1.1
Cookie: account=carlos
verification-code=123456
```
Log in with your own account through step 1, then at the verify step change `account` (or equivalent param/cookie) to the victim and submit a (brute-forced) code. If accepted, you get the victim's session without their password or device.

### 2.3 Brute-forcing verification codes
Codes are often a 4-6 digit number (small keyspace). Per-attempt "log you out after failed code" defenses are ineffective if you automate the *entire* multi-step flow (re-do step 1 + submit next code) using session-handling macros (Burp Intruder/Turbo Intruder). Check for: no rate limit on the OTP endpoint, OTP not invalidated/rotated after failures, OTP reusable, predictable/non-random OTP.

### 2.4 SMS-based 2FA weaknesses
- **Interception** — codes sent over SMS rather than generated locally can be intercepted.
- **SIM swapping** — attacker fraudulently obtains a SIM for the victim's number and receives the code. (Out of scope for app testing, but note as design risk.)

---

## 3. Other mechanisms

Ref: https://portswigger.net/web-security/authentication/other-mechanisms

### 3.1 Keep-me-logged-in / remember-me cookies
The persistent cookie lets attackers bypass login attempt limits entirely (target the cookie, not the form).
- **Predictable construction** — often a concatenation of static values: username + timestamp, or a hash of username+password. Register your own account, decode/inspect the cookie, deduce the formula, then forge cookies for other users.
- **Weak encoding** — Base64 is encoding, not protection. Unsalted hashes can be cracked by hashing a wordlist with the identified algorithm; cleartext passwords recovered via rainbow tables.
- **Framework leakage** — open-source frameworks document their cookie construction; read the docs to reverse it.
- **Theft** — cookies stealable via XSS, then replayed.

### 3.2 Password reset — broken logic
- **Editable user param:** reset request/confirm carries `user=victim`; change it to reset an arbitrary account's password.
- **Token not re-validated on submit:** if the token is checked when the page loads but not when the new password is submitted, request a reset for *your own* account, delete/blank the token on the form, and submit — then reuse that token-less request against a victim.
- **Predictable tokens:** sequential, short, time-seeded, or low-entropy tokens can be guessed/brute-forced. Tokens should be high-entropy, single-use, time-limited, and bound to the account.

### 3.3 Password reset poisoning
Ref: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
When the reset URL is built from a controllable header, redirect the victim's token to your server:
1. Submit a reset for the victim; intercept the request and set `Host: attacker.tld` (or inject `X-Forwarded-Host: attacker.tld`).
2. App emails a genuine token but with the link pointing at `https://attacker.tld/reset?token=...`.
3. Victim (or an automated scanner/AV that fetches links) hits the URL; the token lands in your server logs.
4. Use the stolen token on the real site to set the victim's password -> ATO.

If you can't control the link host, you can sometimes inject HTML into the email (dangling-markup) via the Host header to exfiltrate the token.

### 3.4 Password change
- **Hidden username field:** change form often includes a hidden/editable `username`; edit it to target an arbitrary account without authenticating.
- **Reused validation logic:** the change-password endpoint can leak via the same enumeration/error-message and brute-force techniques as login (e.g. "current password incorrect" vs "username invalid"), and may lack rate limiting.

---

## 4. Prevention (for triage / report recommendations)

- Identical, generic responses and timing for all login/reset/enumeration outcomes.
- Robust, layered brute-force protection: per-account and per-IP, defenses that don't reset on success, CAPTCHA/step-up, and rate limit the OTP endpoint.
- Bind every auth step (2FA verify, reset, change) to the authenticated session/user server-side; never trust client-supplied identifiers.
- High-entropy, single-use, short-lived, account-bound reset tokens; re-validate on submit.
- Generate reset URLs from server-side configured hostnames, never from the Host/forwarded headers.
- Avoid client-side persistence secrets; if used, sign/encrypt with a server secret and salt; prefer rotating session tokens.
- Enforce strong-password policy and MFA; avoid HTTP Basic over non-HSTS transport.

---

## 5. Triage checklist (impact-first)

- [ ] Does the finding reach **account takeover**? If yes -> high signal, prove with a controlled test account and log to `./_EXPLOIT/`.
- [ ] If only enumeration / missing rate-limit / weak policy -> is there a working follow-on exploit? If not -> do **not** report (noise).
- [ ] Is the PoC minimal, safe, and against an account you control, within scope and rate-limit rules?
- [ ] Does the `_EXPLOIT/` entry include the request sequence, the exact mutated field, the victim resource returned, and the concrete impact?
