# Reporting — deep reference

A fuller companion to `SKILL.md`. Aligns with the workspace doctrine: lead with business impact, be reproducible, be honest about severity, and keep signal high.

---

## 1. Worked example — full IDOR report

> Use this as a model for shape, tone, and the level of concreteness expected.

```markdown
# IDOR in GET /api/v2/invoices/{id} allows any user to read other tenants' invoices

**Affected asset:** https://app.example.com/api/v2/invoices/{id}  (in scope per program policy, "*.example.com app APIs")
**Severity:** High — any authenticated user can read arbitrary customers' billing PII; no credential exposure, requires a (free) account.
**CVSS v3.1 (support):** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 (Medium-High). Adjusted up to High in reasoning below: the data is regulated PII and the entire invoice table is enumerable.

## Summary / Business Impact
The invoice API authorizes the request by session but never checks that the requested invoice belongs to the caller's account. Any logged-in user can iterate `{id}` (sequential integers) and read every other customer's full invoice: billing name, address, email, card last-4, and line items. With ~sequential IDs, the entire customer billing dataset is enumerable by a single low-privilege account. This is a mass PII exposure affecting all paying customers.

## Reproduction Steps
Prerequisites: two test accounts, A (attacker) and B (victim), each with at least one invoice. Capture A's session cookie/bearer token.

1. As victim B, create/locate an invoice; note its id (e.g. `48213`).
2. As attacker A, authenticate and capture the bearer token.
3. Request B's invoice using A's token:
   - Expected (secure): `403 Forbidden` (not your invoice).
   - Actual: `200 OK` with B's full invoice body.
4. Decrement/increment the id to confirm enumeration across other tenants.

## Minimal PoC
```bash
# A's token reads B's invoice 48213
curl -s https://app.example.com/api/v2/invoices/48213 \
  -H "Authorization: Bearer $A_TOKEN" | jq '{id, billing_name, email, card_last4}'
# -> {"id":48213,"billing_name":"<B's name>","email":"<B's email>","card_last4":"4242"}
```
(Logged at ./_EXPLOIT/idor_invoices.sh)

## Impact Details
- Every invoice id appears sequential; sampling 20 IDs returned 20 distinct tenants' data → full-table enumeration is trivial.
- Data per record: name, postal address, email, card last-4, purchased items/amounts → regulated PII + partial financial data.
- No interaction or elevated privilege needed beyond a standard account.
- Does not expose full PANs, passwords, or write access (hence High, not Critical).

## Remediation
Enforce object-level authorization: verify the invoice's owning account == caller's account before returning it; return 403/404 otherwise. Consider non-sequential identifiers (UUIDs) as defense-in-depth, but the authz check is the fix.

## Supporting Evidence
Trimmed 200 response with PII redacted (see attached `invoice_redacted.json`).
```

Why this works: title states class+asset+impact; impact leads and quantifies scale; repro is two-account and copy-pasteable; PoC is one curl; severity is reasoned, not just a CVSS number; remediation names the real fix.

---

## 2. Severity / CVSS rubric (with worked scoring)

Severity = **impact × likelihood**, judged in context. CVSS gives a defensible number; the *sentence of reasoning* is what triagers trust.

CVSS v3.1 base metrics to set:
- **AV** Attack Vector: Network / Adjacent / Local / Physical
- **AC** Attack Complexity: Low / High
- **PR** Privileges Required: None / Low / High
- **UI** User Interaction: None / Required
- **S** Scope: Unchanged / Changed (does it break out of its security authority?)
- **C/I/A** Confidentiality / Integrity / Availability impact: None / Low / High

Worked examples:
- **Unauth SQLi dumping the users table** — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N ≈ 9.1 → **Critical**. No auth, full read/write of sensitive data.
- **IDOR reading PII (authed)** — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 → base **Medium-High**; argue **High** when data is regulated/mass-enumerable.
- **Reflected XSS, obscure param, victim click** — AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N ≈ 6.1 → **Medium**. UI required + limited reach lowers it.
- **SSRF reaching cloud metadata** — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N ≈ 8–9 → **High/Critical** if it yields credentials.
- **Missing security header, no demonstrated impact** — not a finding on its own → don't submit.

Adjustment rules of thumb:
- Sensitive/regulated data or mass enumeration → push up.
- Requires unrealistic preconditions, niche config, or victim doing something abnormal → push down.
- "Chains into X" only counts if you actually demonstrate the chain.

---

## 3. Impact statements — do / don't

DO:
- State the concrete consequence: what data, whose, how much, what action.
- Quantify scale ("any of N users", "entire table", "all tenants").
- Be honest about limits ("read-only", "requires authenticated account", "no PAN exposed").
- Connect to business: money, PII, account takeover, trust/compliance.

DON'T:
- "Could potentially lead to serious consequences" — vague, no consequence.
- Label everything Critical / "full compromise" without proof.
- Minimize a real issue to sound modest ("just an IDOR") — state it plainly.
- Claim impact you didn't demonstrate (speculative chaining, assumed prod data).

---

## 4. PoC & screenshot hygiene

- **Minimal**: the fewest steps/requests that prove it. Prefer a single curl over a Burp project.
- **Reproducible**: parameterize tokens/IDs (`$A_TOKEN`, `{id}`) so the triager substitutes their own.
- **Self-contained**: include the request AND the meaningful part of the response.
- **Store proven exploits** in `./_EXPLOIT/` (minimal curl preferred) and reference the file in the report.
- **Screenshots**: only when they add what text can't (rendered XSS alert, UI state). Crop to the relevant area, annotate, redact secrets. Never rely on a screenshot in place of a copy-pasteable request.
- **No noise**: strip irrelevant headers, cookies, and unrelated traffic.

---

## 5. Responsible handling of sensitive data

- Use your **own test accounts** (A/B) wherever possible. Don't pull more real user data than needed to prove impact — a single record is enough; don't dump the table.
- **Redact** PII/secrets in the report: mask card numbers (`4242`/last-4 only), truncate tokens, blur names/emails/addresses in screenshots.
- Don't exfiltrate, store, or share victim data beyond the minimal proof. Note in the report that you stopped at proof-of-concept.
- Don't pivot/escalate beyond what's needed to demonstrate the issue, and stay within program scope and rules of engagement.
- If you incidentally accessed sensitive data, say so and describe how you handled/deleted it.

---

## 6. Pre-submission checklist

- [ ] Pre-flight gate passed: working PoC, proven impact, in-scope asset, clears impact bar.
- [ ] Title = class + asset + impact, one line.
- [ ] Report leads with business impact, quantified.
- [ ] Severity stated with a sentence of reasoning; CVSS vector included as support.
- [ ] Repro steps are numbered, exact, copy-pasteable; prerequisites listed.
- [ ] Minimal PoC included and stored in `./_EXPLOIT/`.
- [ ] Remediation is concrete and names the actual fix.
- [ ] Duplicate / known-issue / accepted-risk / best-practice-nit check done.
- [ ] Sensitive data redacted; only minimal data accessed; cleanup noted.
- [ ] Re-read once: is every impact claim honest and demonstrated?
```
