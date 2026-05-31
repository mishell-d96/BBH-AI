# Access Control & IDOR — Deep Reference

Sources:
- https://portswigger.net/web-security/access-control
- https://portswigger.net/web-security/access-control/idor

Access control rests on three pillars: **authentication** (who you are), **session management** (tracking your requests), and **access control decisions** (whether you may perform the action). Broken access control occurs when a user can act outside their intended permissions. It is widespread because correct enforcement must be applied at every entry point and is easy to miss.

---

## 1. Categories of access control

### Vertical access controls
Restrict sensitive functionality to specific user *types* (e.g. admin vs ordinary user). Enforce separation of duties and least privilege. Breaking them = **vertical privilege escalation** (a non-admin performing admin actions).

### Horizontal access controls
Restrict a resource to its specific owner. Different users get only their own subset (e.g. a bank user sees only their own accounts/transactions). Breaking them = **horizontal privilege escalation** (accessing another user's resources of the same privilege level).

### Context-dependent access controls
Restrict access based on application state or the order of interactions — e.g. you cannot modify a shopping cart after payment. Breaking them = performing an action out of the intended sequence.

---

## 2. Vertical privilege escalation

### 2.1 Unprotected functionality
Privileged functionality has no server-side enforcement; reaching the URL is enough.
- Direct access: `https://insecure-website.com/admin`.
- Discovery: links in `robots.txt`, wordlist/brute-force of common admin paths.
- **Security through obscurity**: "hidden" URLs like `https://insecure-website.com/administrator-panel-yb556` are not protected — they are commonly leaked in client-side JavaScript that builds menus based on the user's role. Read the JS.

### 2.2 Parameter-based access control
Role/rights are read from a **user-controllable** location: hidden form field, cookie, or query parameter. Tamper to escalate.
- `https://insecure-website.com/login/home.jsp?admin=true`
- `https://insecure-website.com/login/home.jsp?role=1`
- Cookie like `Admin=false` -> set `true`; hidden field `isAdmin`.

### 2.3 Broken access control from platform misconfiguration
Controls applied at the platform/gateway layer by restricting URLs and HTTP methods can be bypassed.

**Non-standard headers** — some frameworks let a header override the requested URL, bypassing front-end path rules:
```
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
```
Also `X-Rewrite-URL`. If the front-end allows `/` but the back-end honors the header, the restricted path is reached.

**HTTP method switching** — a restriction on `POST /admin/deleteUser` may not cover other verbs. Try `GET`, or other methods, with parameters moved to the query string.

### 2.4 Broken access control from URL-matching discrepancies
The component enforcing access and the component routing the request normalize URLs differently.
- **Case**: `/ADMIN/DELETEUSER` enforced as public but routed to `/admin/deleteUser`.
- **Suffix**: Spring's `useSuffixPatternMatch` (default-on before Spring 5.3) maps `/admin/deleteUser.anything` to `/admin/deleteUser`.
- **Trailing slash**: `/admin/deleteUser/` may be treated differently from `/admin/deleteUser` by one of the two layers.

---

## 3. Horizontal privilege escalation

A user accesses another user's resources of the same type. Classic pattern:
```
https://insecure-website.com/myaccount?id=123   ->   ?id=124
```
- **Predictable IDs** (incrementing integers) are trivially guessed.
- **GUIDs/UUIDs** resist guessing but are frequently **disclosed elsewhere** — in messages, reviews, profile pages, API list endpoints, or comments — making them usable.
- **Redirect leakage**: even when the app redirects an unauthorized request (e.g. to login), the response may still contain the sensitive data in the body. Inspect the full response, not just the status.
- Applies to **modification** too: changing email, resetting password, transferring funds via the victim's ID.

---

## 4. Insecure Direct Object References (IDOR)

A subcategory of access control where the application uses **user-supplied input to access objects directly**, and the attacker modifies the input to gain unauthorized access. Popularized in the **OWASP 2007 Top Ten**. Most commonly horizontal, but can be vertical.

### 4.1 Reference to database objects
```
https://insecure-website.com/customer_account?customer_number=132355
```
`customer_number` is the direct DB key. Changing it returns another customer's record when no ownership check exists.

### 4.2 Reference to static files
Sensitive data saved to the filesystem with predictable names is the same flaw at the file layer:
```
https://insecure-website.com/static/12144.txt
```
e.g. chat transcripts stored as sequential `.txt` files — altering the number retrieves another user's transcript. No authorization layer protects raw static files.

### 4.3 Detection / exploitation
Identify user-controlled parameters (IDs, filenames, user identifiers), then test alternative values. Often no sophistication is needed — simple parameter manipulation succeeds when authorization validation is absent. Confirm with a second account and compare responses.

---

## 5. Horizontal -> vertical privilege escalation
Use a horizontal break to compromise a **higher-privileged** user, then inherit their privileges.
1. Exploit horizontal access to reach an admin user's account/details.
2. Read or reset the admin's password (e.g. the same vulnerable `?id=` endpoint exposes a password field, or lets you set a new one).
3. Authenticate as admin and use administrative functionality.

---

## 6. Multi-step process flaws
Sensitive functions implemented over several steps (e.g. load form -> submit changes -> confirm) sometimes enforce access only on early steps and **assume** the user must have passed them.
- Attack: skip the guarded steps and submit the **final** request directly with all required parameters. If the final step doesn't re-verify privilege, it executes.

---

## 7. Referer-based access control
Some apps enforce access on a main page (e.g. `/admin`) but, for sub-actions (e.g. `/admin/deleteUser`), trust the `Referer` header to confirm the request came from the admin page.
- The `Referer` header is fully attacker-controlled. Forge `Referer: https://target/admin` on the sub-action request to bypass the check.

---

## 8. Location-based access control
Access restricted by geographic location (e.g. region-locked media, banking). Circumvented with:
- Web proxies, VPNs, or exit nodes in the permitted region.
- Manipulation of client-side geolocation. Client-supplied location is not an access control.

---

## 9. Prevention principles
- Never rely on obfuscation / hidden URLs alone.
- **Default-deny** for any resource not intentionally public.
- Use a single, application-wide access-control mechanism; don't reimplement per endpoint.
- Force developers to **declare the allowed access** for each resource; deny by default in code.
- Don't trust user-controllable inputs (params, cookies, hidden fields, `Referer`, geolocation) for authorization decisions.
- Use unpredictable identifiers, but treat them as defense-in-depth — still enforce ownership checks server-side.
- Audit and test access controls thoroughly, including method/URL-normalization edge cases.

---

## 10. Bug-bounty testing checklist
- [ ] Two low-priv accounts + (if possible) one admin enrolled.
- [ ] Every object-referencing request replayed cross-account (read + write).
- [ ] Static-file IDs and download/export endpoints tested.
- [ ] Forced browsing of admin paths; read client JS for hidden URLs; check `robots.txt`.
- [ ] Parameter/cookie/hidden-field role tampering (`admin`, `role`, `isAdmin`).
- [ ] Method switch; URL case/suffix/trailing-slash quirks; `X-Original-URL` / `X-Rewrite-URL`.
- [ ] Multi-step flows: jump straight to the final guarded step.
- [ ] `Referer`-gated sub-actions; geo/IP-gated content.
- [ ] Inspect redirect bodies for leaked data.
- [ ] Scope gate: prove with your own object + ONE controlled test object; never harvest real user data; log to `./_EXPLOIT/` with a minimal curl repro.
