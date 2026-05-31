---
name: authentication
description: Find and prove authentication vulnerabilities in login, registration, password reset/change, and 2FA flows that lead to account takeover. Use when testing login/register/reset/2FA flows, username enumeration, brute-force/lockout protection, remember-me cookies, password reset tokens, OTP/verification codes, credential stuffing, or any account takeover (ATO) chain.
---

## When to test

Any credential-handling surface:
- **Login** — username/password, "invalid credentials" messaging, lockout behavior.
- **Registration** — username collision responses (enumeration), weak self-service.
- **Password reset** — token generation, token validation, reset link construction (Host header).
- **Password change** — does it re-verify identity? hidden username fields?
- **2FA / MFA** — verification-code step, step-skipping, OTP brute-force.
- **"Stay logged in" / remember-me** — cookie structure and forgeability.

## Impact & priority

Impact-first, honest framing:
- **High signal:** full **account takeover** (2FA bypass, reset-token theft/forgery, remember-me cookie forgery, password-change of arbitrary account). These are reportable on their own.
- **Medium:** flawed brute-force protection that demonstrably enables credential brute-force/stuffing against real accounts (prove with a test account you control).
- **Low / often noise alone:** username enumeration with no follow-on, missing rate-limit with no working exploit, weak-password-policy nits. Only report enumeration if it *enables* an ATO chain.

Always confirm scope and rate-limit rules before any guessing. Brute-force/credential-testing ONLY where explicitly permitted, and ONLY against test accounts you control.

## Detection

**Username enumeration** — look for differences between valid and invalid usernames:
- Response status codes that differ.
- Error message wording (even a trailing space / single-char diff — diff responses byte-for-byte).
- Response timing — valid user triggers password hashing; amplify by submitting a very long password and comparing latency.
- Also via registration ("username taken") and reset ("no such email") flows.

**Flawed brute-force protection:**
- Lockout that triggers on N failures but resets on a *successful* login to an attacker account — interleave to reset the counter.
- IP-based blocking bypassable via `X-Forwarded-For` / `X-Forwarded-Host` spoofing or proxy rotation.
- Lockout keyed on case/whitespace-normalized username but auth checks the raw value (e.g. `Carlos` vs `carlos`, trailing space).
- Multiple password guesses accepted in a single request (array/JSON).

**2FA logic flaws:**
- Does the app verify the second step was completed before serving authenticated pages? Try navigating straight to a post-login page after step 1.
- Is the verification step bound to the session/user from step 1, or to a tweakable `account` cookie/param?
- No rate limit on the OTP endpoint; session not invalidated after failed codes.

**Reset token weaknesses:**
- Predictable/sequential/short tokens; token tied to a `user` param you can change.
- Token not re-validated on submit (delete your own token, reuse the URL against a victim).
- Reset URL built from the `Host`/`X-Forwarded-Host` header (poisoning).

## Exploitation

- **Credential brute-force (permitted only):** spray 3-5 common passwords across many candidate usernames (stays under per-account lockout); or credential-stuffing one breach password per username.
- **2FA bypass:** (a) skip the verification request and load the authenticated page directly; (b) change the `account`/`user` value on the verify request to the victim while supplying a brute-forced code; (c) brute the 4-6 digit OTP by automating the full multi-step flow (macro/session-handling) so per-attempt logout doesn't matter.
- **Password reset:** change the `user`/`email` param to a victim; or capture a victim token via reset poisoning (`Host: attacker.tld`) and use it on the real site; or exploit predictable tokens.
- **Remember-me cookie forgery:** register your own account, decode the cookie (often `base64`/unsalted hash of `username` + static), deduce the formula, forge a victim's cookie.
- **Account takeover chains:** enumeration -> targeted brute-force/reset -> ATO; or password-change endpoint with editable hidden `username` -> set victim's password directly.

## Common bypasses

- Lockout evasion via username case/whitespace variants, or response truncation hiding the real outcome.
- IP-block evasion via forwarded-for headers / rotation (only if permitted).
- See `reference.md` for the full catalogue.

## Minimal PoC

Keep it minimal and SAFE; log proven exploits to `./_EXPLOIT/` with a curl repro. Example 2FA logic-flaw ATO:

```
# 1. Authenticate as YOUR test account through step 1 (sets session cookie)

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.

curl -s https://target/login -d 'username=attacker&password=Test123!' -i
# 2. At the verify step, swap the account binding to the victim, brute the code
curl -s https://target/login-steps/second \
  -H 'Cookie: account=victim; session=<from step 1>' \
  -d 'verification-code=0001'   # iterate 0000-9999 until 302 -> /my-account
# 3. Confirm: authenticated request now returns victim's account page
```

`_EXPLOIT/` entry: request sequence, the exact mutated field, the victim resource returned, and impact (full ATO without victim's password/OTP).

## Don't report as noise

- Username enumeration with no demonstrated follow-on ATO.
- "No rate limiting" without a working brute-force/OTP exploit.
- Weak password policy, missing HSTS on basic-auth, generic "2FA should exist" notes.
- Anything proven only against accounts you don't own or outside scope/rate-limit rules.

## Deep reference

See `reference.md` for full techniques. Sources:
- https://portswigger.net/web-security/authentication
- https://portswigger.net/web-security/authentication/password-based
- https://portswigger.net/web-security/authentication/multi-factor
- https://portswigger.net/web-security/authentication/other-mechanisms
- https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
