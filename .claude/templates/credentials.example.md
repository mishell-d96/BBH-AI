# Test Identities — <target>

Copy this file to `scope/credentials.md` and fill in **only** credentials the program issued you or
explicitly authorized you to create. `scope/*` is gitignored, so real creds never get committed.
Never put production/third-party creds here. Re-confirm in `scope/` that authenticated testing is permitted.

## Why two low-priv accounts
Broken access control (your top-priority class) is proven by **diffing vantage points**: what user A
can do to user B's objects, and what an unauthenticated client can reach. Always keep these ready so
every candidate can be checked from each angle without re-provisioning mid-test.

| Identity | Role / tenant | Username | Secret (or how to obtain) | Session token / cookie | Notes |
|----------|---------------|----------|---------------------------|------------------------|-------|
| unauth | none | — | — | — | baseline: what's reachable with no session |
| user_A | low-priv, tenant 1 | | | | the "attacker" account |
| user_B | low-priv, tenant 2 | | | | the "victim" account — A must NOT reach B's data |
| admin | privileged | | | | only if the program issued admin access |

## Capturing sessions
- Log in as each identity, capture the session cookie / bearer token, paste above (redact in any report/artifact).
- Refresh tokens when they expire; note expiry so a stale token isn't mistaken for an access-control fix.

## Access-control diff routine (per candidate)
1. Perform the action as **user_A** on **user_A's** object → expect success (baseline).
2. Repeat against **user_B's** object id/reference → success here = horizontal IDOR/BOLA.
3. Repeat **unauthenticated** → success = missing authn.
4. For privileged actions, attempt as **user_A** → success = vertical privilege escalation.
Hand confirmed results to `access-control-idor` / `authentication`, then `_EXPLOIT/` + `/reporting`.
