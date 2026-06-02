---
name: reporting
description: "Draft a clear, reproducible, impact-led vulnerability report from a validated finding. Use when writing up a finding, drafting repro steps, assessing severity/CVSS, duplicate-checking, or before submitting. Covers structure, impact statement, minimal PoC, remediation, fill-in template."
---

# Reporting — validated finding → high-signal report

Goal: turn a *proven* finding into a report a triager can verify in minutes and that leads with business impact. Optimize for signal-to-noise. Never inflate, never trivialize.

## Pre-flight gate — do NOT write a report unless ALL hold
1. **Working minimal PoC exists** — you can reproduce it on demand (ideally a logged curl in `./_EXPLOIT/`).
2. **Impact is proven, not speculative** — you demonstrated the consequence, not just a "could theoretically".
3. **Asset confirmed in scope** — the affected host/app/endpoint is in the program's scope, and the bug class isn't out-of-scope.
4. **Clears the impact bar** — it's a real security issue, not noise (no missing-header nits, no self-XSS, no theoretical CSRF on unauthenticated/no-state endpoints).

If any fail → **stop. Do not submit.** Go finish the PoC, prove the impact, or drop it.

## Report structure (in this order)
1. **Title** — vuln class + asset + impact in one line. e.g. "IDOR in /api/v2/invoices lets any user read other tenants' invoices".
2. **Affected asset** — exact URL/host/endpoint, confirmed in scope.
3. **Severity + reasoning** — impact × likelihood. Cite CVSS as *support*, not a substitute for a sentence of reasoning.
4. **Summary / business impact** — LEAD WITH THIS. What an attacker gains in business terms (data exposed, accounts taken over, money moved).
5. **Reproduction steps** — exact, numbered, copy-pasteable.
6. **Minimal PoC** — curl preferred, drawn from `./_EXPLOIT/`. Smallest thing that proves it.
7. **Impact details** — scope/scale: how many users, what data, whether it chains.
8. **Remediation** — concrete, actionable fix.
9. *(optional)* **Supporting evidence** — trimmed responses, redacted screenshots.

## Writing impact statements
Be concrete and honest. Tie to a business consequence: data exposed, accounts affected, money, trust. State scale when you can ("any authenticated user can read *any* other user's records").

Good vs bad:
- BAD (vague): "This could potentially be exploited by an attacker." → no consequence stated.
- BAD (inflated): "Critical RCE-level breach of the entire platform" for a reflected XSS needing a victim click on an obscure param.
- GOOD: "Any logged-in user can change `?account_id=` to read another customer's full billing address, card last-4, and invoice history. Tested across 3 accounts; no authz check on the endpoint."
- GOOD (honest downgrade): "Reflected XSS in the search param; requires the victim to click a crafted link and the param isn't shared in normal flows, so likelihood is moderate."

If you can't write one honest concrete sentence of impact, you don't have a report yet.

## Severity guidance (context decides — reason it through)
Typical *starting points*, adjusted by auth requirements, scope, and data sensitivity:
- **Critical** — RCE, auth bypass to admin, SQLi dumping data, account takeover with no interaction, full IDOR over sensitive data across tenants.
- **High** — stored XSS in authed context, SSRF reaching internal services, IDOR on sensitive data, privilege escalation.
- **Medium** — reflected XSS, CSRF on a meaningful state-changing action, info disclosure of moderate data, open redirect feeding a real attack.
- **Low** — limited info disclosure, self-XSS chains, issues requiring unrealistic preconditions.
Always write *why*: e.g. "High, not Critical — IDOR exposes PII but not credentials, and requires an authenticated account." Use CVSS vectors to support the number, never to replace the reasoning.

## Reproducibility
A triager should reproduce in minutes. Include:
- **Prerequisites** — accounts needed (e.g. two test users A and B), tokens, roles, any setup.
- **Exact requests** — full method, path, headers that matter, body. Mark where to substitute IDs/tokens.
- **Expected vs actual** — what a secure system would do vs what happens.
- **Cleanup** — undo any state you changed; note if data was created/modified.

## Duplicate & quality check
- Conceptually check for dupes: is this a known issue, recently patched, or already-reported pattern on this asset?
- Is it a **known-accepted risk** or documented behavior? (Check program policy / prior disclosures.)
- Is it a pure **best-practice nit** with no demonstrable impact? → don't submit.
- One bug per report unless they genuinely chain into a single impact.

## Template (fill in)
```markdown
# [Title: vuln class in <asset> — <impact>]

**Affected asset:** <exact in-scope URL/host/endpoint>
**Severity:** <Critical/High/Medium/Low> — <one sentence: impact × likelihood>
**CVSS (support):** <vector / score, optional>

## Summary / Business Impact
<Lead here. What an attacker gains, in business terms, and at what scale.>

## Reproduction Steps
Prerequisites: <accounts/tokens/roles>
1. <step>
2. <step>
3. <observe: expected vs actual>

## Minimal PoC
```bash
<minimal curl from ./_EXPLOIT/>
```

## Impact Details
<Scope/scale: how many users, what data, chaining potential.>

## Remediation
<Concrete fix.>

## Supporting Evidence (optional)
<Trimmed responses / redacted screenshots.>
```

## Deep reference
See `reference.md` for a full worked IDOR report, a severity/CVSS rubric with worked scoring, impact-statement do/don't lists, PoC & screenshot hygiene, sensitive-data handling, and a pre-submission checklist.
