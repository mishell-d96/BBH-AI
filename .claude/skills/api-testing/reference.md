# API Testing — Deep Reference

Authoritative sources:
- https://portswigger.net/web-security/api-testing
- https://portswigger.net/web-security/api-testing/server-side-parameter-pollution

Cross-reference: the **access-control-idor** skill (object/function-level authorization, ownership checks) — most high-impact API findings are ultimately authz failures reached through an API-specific vector. Run the **recon** skill for initial surface discovery.

---

## 1. API recon

An API endpoint is a location where the API receives requests about a specific resource. Recon goal: map the attack surface — endpoints, parameters, supported HTTP methods, content types, auth mechanisms, and rate limits.

### 1.1 Documentation discovery
- Two forms: **human-readable** (developer docs) and **machine-readable** (JSON/XML, e.g. OpenAPI/Swagger) for automated consumption.
- Even if not advertised, docs are often reachable via the app that uses the API. Probe common paths:
  - `/api`
  - `/swagger/index.html`, `/swagger-ui.html`, `/swagger.json`
  - `/openapi.json`, `/api-docs`, `/v2/api-docs`, `/v3/api-docs`
- **Walk parent paths.** From a known resource endpoint like `/api/swagger/v1/users/123`, try `/api/swagger/v1`, `/api/swagger`, `/api` — docs frequently live at an ancestor path.
- Tools: Burp Scanner crawls and audits OpenAPI docs; OpenAPI Parser BApp parses spec files; Postman and SoapUI drive endpoints from specs.

### 1.2 Identifying endpoints
- Burp Scanner crawl; manual browsing of the consuming app.
- Analyze JavaScript bundles — JS Link Finder BApp extracts endpoint references; grep JS for `/api/`, `fetch(`, `axios`, route tables.
- Recognize patterns: `/api/`, versioned paths (`/v1/`), resource/ID structures.

### 1.3 Interacting with endpoints — HTTP methods
- APIs map verbs to actions: `GET` read, `POST` create, `PATCH` partial update, `PUT` replace, `DELETE` remove, `OPTIONS` lists permitted methods.
- Example family: `GET /api/tasks`, `POST /api/tasks`, `DELETE /api/tasks/1`.
- Use Burp Intruder's built-in HTTP-verbs list to cycle methods automatically.
- **Safety:** test method changes on low-priority / disposable objects to avoid destructive side effects.

### 1.4 Interacting with endpoints — content types
- Different `Content-Type` values can trigger different server behavior. Try switching `application/json` <-> `application/xml` <-> `application/x-www-form-urlencoded`.
- Payoffs: revealing error detail, bypassing input filters tuned to one format, and reaching a parser with different security properties (e.g. an XML parser vulnerable to XXE where JSON was safe).
- Content Type Converter BApp auto-converts request bodies between XML and JSON.

---

## 2. Finding hidden endpoints

- Use Burp Intruder against a known endpoint structure, substituting the action segment. From `PUT /api/user/update`, fuzz `/update` -> `delete`, `add`, `create`, `remove`, `edit`, etc.
- Build wordlists from: common API naming conventions, industry/domain terms, and application-specific vocabulary harvested during recon.
- Look for undocumented verbs and undocumented sibling resources.

---

## 3. Finding hidden parameters

- **Burp Intruder**: brute-force parameter names from a common-names wordlist.
- **Param Miner BApp**: guesses up to 65,536 parameter names per request and auto-flags ones the app actually uses.
- **Content Discovery**: surfaces linked content including parameters.
- Strongest signal source: compare what an object **returns** vs. what the edit form **accepts** — extra returned fields are candidate hidden writable params.

---

## 4. Mass assignment

Mass assignment (auto-binding) occurs when a framework automatically maps request fields onto internal object properties, including ones never meant to be user-controlled.

### Identifying
A `GET /api/users/123` returning:
```json
{"id": 123, "name": "John Doe", "email": "john@example.com", "isAdmin": "false"}
```
implies `id` and `isAdmin` may be bindable on update even though the UI never sends them.

### Testing methodology
1. Add the suspected field to an update request (e.g. `PATCH /api/users/`).
2. First send an **invalid** value and observe whether behavior/error changes — confirms the field is read.
3. Then send a **valid privileged** value to attempt exploitation:
   ```json
   {"username": "wiener", "email": "wiener@example.com", "isAdmin": true}
   ```
4. Confirm impact by verifying the account actually gained the privilege (re-read self, access a privileged action).

Common privileged fields: `isAdmin`, `role`, `roles`, `access_level`, `group`, `verified`, `balance`, `id`/`user_id` (to write another user's object — overlaps with IDOR).

---

## 5. Server-side parameter pollution (SSPP)

SSPP arises when a site embeds user input into a **server-side** API request without proper encoding, letting an attacker override or inject parameters in the internal request.

### 5.1 Query-string SSPP
- **Truncate with `%23` (`#`):** terminates the server-side query string, dropping parameters the server appends.
  - `GET /userSearch?name=peter%23foo&back=/home`
  - server-side becomes `GET /users/search?name=peter#foo&publicProfile=true` — the `#` cuts off `publicProfile=true`, potentially exposing non-public records.
- **Inject with `%26` (`&`):** add an extra parameter to the server-side request.
  - `GET /userSearch?name=peter%26foo=xyz&back=/home` -> `GET /users/search?name=peter&foo=xyz&publicProfile=true`. Tells you whether injected params are processed.
- **Override duplicate params:** inject a duplicate name to override the value; resolution is stack-dependent:
  - **PHP** — last value wins (`carlos`).
  - **ASP.NET** — values combined (`peter,carlos`).
  - **Node.js / Express** — first value wins (`peter`).
- Useful encodings: `%23` = `#`, `%26` = `&`, `%3d` = `=`.

### 5.2 REST-path SSPP
- When user input lands inside a URL path segment, use URL-encoded path traversal to redirect the server-side route.
  - `GET /edit_profile.php?name=peter%2f..%2fadmin` may normalize server-side to `/api/private/users/admin`.

### 5.3 Structured data format injection (JSON/XML)
- **Form input folded into JSON:** break out of the string value and add sibling fields.
  - `POST /myaccount` with `name=peter","access_level":"administrator`
  - becomes `PATCH /users/7312/update {"name":"peter","access_level":"administrator"}`.
- **JSON request re-serialized server-side:** inject via escaped quotes.
  - `{"name": "peter\",\"access_level\":\"administrator"}` -> elevated privilege if improperly encoded.
- XML equivalents: inject closing/opening tags to add elements server-side.

### 5.4 Detection
- Burp Scanner flags **suspicious input transformation** during audit.
- Backslash Powered Scanner classifies inputs as boring / interesting / vulnerable to focus investigation.

---

## 6. Testing beyond intended use
- Combine the above: change method + change content type + add hidden params simultaneously.
- Treat reachable params as injection surface — pivot into SQLi, SSRF, NoSQLi, IDOR.
- Test all API versions, not just the current one — old versions often lack the latest authz checks.

---

## 7. OWASP API Security Top 10 alignment
- **API1 Broken Object Level Authorization (BOLA/IDOR)** — see access-control-idor skill.
- **API2 Broken Authentication.**
- **API3 Broken Object Property Level Authorization** — includes mass assignment and excessive data exposure.
- **API5 Broken Function Level Authorization** — method/verb tampering reaching privileged functions.
- **API6 Unrestricted Access to Sensitive Business Flows.**
- **API7 Server-Side Request Forgery** — pivot target from injectable params.
- **API9 Improper Inventory Management** — undocumented/old endpoints & versions.
- SSPP maps to broken object/function-level authz when it overrides server-enforced authorization params.

---

## 8. Prevention (for triage / report remediation advice)
- Secure docs that should not be public; keep legitimate docs current.
- Enforce HTTP-method allowlists; validate expected content types.
- Use generic error messages.
- Protect every API version, not only production.
- Mass assignment: allowlist updatable properties and blocklist sensitive ones from user modification.
- SSPP: allowlist characters that need no encoding, encode all other user input before building server-side requests, and validate input against expected format/structure.
