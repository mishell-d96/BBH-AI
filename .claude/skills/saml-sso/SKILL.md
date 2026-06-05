---
name: saml-sso
description: "SAML/SSO flaws -> auth bypass and full ATO. Use for SAMLResponse/SAMLRequest, /saml/acs, /saml/sso, base64 XML assertions, IdP login (Okta/ADFS/Auth0/Keycloak), <saml:Assertion>, <ds:Signature>. Covers XML Signature Wrapping (XSW), signature stripping, key confusion, NameID injection, XXE."
---

# saml-sso — SAML / SSO Assertion Attacks

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Capture the legitimate SAML login baseline before tampering. Test against the impact-scored candidate list and pursue chains to real business impact.

## When to test
Any SAML or SSO login flow. Signals: a `SAMLResponse` POST to an ACS endpoint
(`/saml/acs`, `/saml/consume`, `/sso/saml`, `/Shibboleth.sso/SAML2/POST`), a
`SAMLRequest` redirect to an IdP, base64-encoded (sometimes deflated) XML
containing `<samlp:Response>`, `<saml:Assertion>`, `<saml:NameID>`, and a
`<ds:Signature>` block. If the app federates to Okta/ADFS/Auth0/OneLogin/
Keycloak/Ping, the assertion is the trust boundary — attack it.

## Impact & priority
HONEST: a working SAML auth flaw is **P1 / critical**. If you can forge or
tamper an assertion the SP accepts, you get **full authentication bypass**:
log in as any user, set the NameID to an admin, impersonate arbitrary
accounts, and reach every privileged function behind SSO. This is org-wide
account takeover, not a single-account bug. Do not under-rate it.

## Detection
1. Capture the legitimate login (baseline). Intercept the `SAMLResponse`,
   base64-decode (and inflate if redirect-binding), save the raw XML. Read it
   from the CLI — no Burp needed just to look:
   - POST-binding (`SAMLResponse`/`SAMLRequest` form field, plain base64):
     ```bash
     echo '<SAMLResponse>' | base64 -d | xmllint --format -
     ```
   - Redirect-binding (`?SAMLRequest=`/`?SAMLResponse=` query param, URL-encoded
     + raw-DEFLATE'd before base64):
     ```bash
     python3 -c "import sys,base64,zlib,urllib.parse as u; print(zlib.decompress(base64.b64decode(u.unquote(sys.argv[1])),-15).decode())" '<SAMLRequest>'
     ```
2. Map **what is signed**: is the `<ds:Signature>` over the whole `Response`,
   over the `Assertion`, or both? Note the `Reference URI="#..."` and the
   signed element's `ID`. Unsigned-but-trusted elements are the prize.
3. Note validation inputs: `Destination`, `Recipient`, `Audience`,
   `InResponseTo`, `NotOnOrAfter`, issuer cert / `<ds:KeyInfo>`.
4. Identify the IdP and its library (ruby-saml, python3-saml, simplesamlphp,
   xmlseclibs, OpenSAML) — library = known CVE surface.

## Exploitation
Try in roughly this order; re-submit each tampered `SAMLResponse` to the ACS:
- **Signature stripping** — remove the `<ds:Signature>` entirely. Many SPs
  accept an unsigned assertion ("no signature accepted"). Then edit NameID.
- **Signature exclusion / empty signature** — keep a `<Signature>` shell but
  remove `SignedInfo`/`SignatureValue`, or point `Reference URI` at nothing
  (void canonicalization — digest hashes empty string).
- **XML Signature Wrapping (XSW1-8)** — keep the original valid signature but
  add a second, attacker-controlled assertion/response. Exploit the gap
  between the element the *validator* checks and the element *business logic*
  reads (XPath `//` selectors, attribute/ID collision). See reference.md.
- **NameID comment injection** — `admin@victim.com<!---->.attacker.com`. Some
  XML parsers truncate at the comment, so the SP reads `admin@victim.com`
  while the signature still covers the full string.
- **Key / certificate confusion** — re-sign with your own self-signed cert and
  embed it in `<ds:KeyInfo>`/`<X509Certificate>`; SPs that trust the embedded
  cert instead of a pinned IdP cert accept it. Also try algorithm downgrade.
- **XXE in assertion parsing** — inject a DOCTYPE/external entity into the XML;
  the parser may resolve it (SSRF/file read) before or during validation.
- **Recipient / Audience / Replay** — reuse a captured assertion past
  `NotOnOrAfter`, against a different SP (`Audience` mismatch), or replay it
  (no `InResponseTo`/one-time check). Cross-SP assertion reuse = takeover.

## Chain for impact
- Forge/edit NameID to an **admin** → authenticate → drive `/access-control-idor`
  against admin-only functions to demonstrate privileged actions.
- **XXE** in the assertion parser → hand off to `/xxe-injection` for file read
  / SSRF / internal-service pivot.
- Any successful bypass → impersonate arbitrary in-scope users to show
  account-takeover blast radius (authorized identities only).

## Tooling
**Burp SAML Raider** — decode/edit assertions inline, run all XSW variants,
strip/remove signatures, and re-sign with a generated self-signed cert in one
click. EsPReSSO/SSO Scanner for flow discovery. `flare`/`zlib` for redirect-
binding inflate.

## Minimal PoC
Keep it SAFE and minimal. Log to `./_EXPLOIT/`:
- the **tampered `SAMLResponse`** (raw + decoded XML, the exact field changed),
- the **request** to the ACS that submitted it,
- the **authenticated-as-victim/admin response** (session cookie issued,
  dashboard showing the impersonated identity).
Two artifacts — input that should be rejected, and proof it was accepted.

## Don't report as noise
- Cosmetic XML quirks, whitespace, or pretty-printing with no auth effect.
- A signed assertion you cannot alter and the SP correctly rejects every
  tamper — that's the control working.
- Self-signed cert *generated* but rejected by the SP (no bypass).
- Replay blocked by `NotOnOrAfter`/`InResponseTo`. No bypass = no report.

## Deep reference
See `reference.md` for XSW1-8 mechanics, library CVEs, and validation rules.
- https://portswigger.net/research/the-fragile-lock
- https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- https://web-in-security.blogspot.com/2019/07/testing-saml-endpoints-for-xml.html
