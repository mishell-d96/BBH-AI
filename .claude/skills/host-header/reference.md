# Host Header Attacks — Deep Reference

Sources:
- https://portswigger.net/web-security/host-header
- https://portswigger.net/web-security/host-header/exploiting

## 1. What the Host header is and how it is used

The `Host` header is a mandatory HTTP/1.1 request header. It tells the receiving server which domain the client wants:

```
GET /web-security HTTP/1.1
Host: portswigger.net
```

It exists because many sites share one IP. Two infrastructure patterns rely on it:

- **Virtual hosting:** a single server hosts multiple sites/applications; the Host header selects which one.
- **Reverse proxy / load balancer routing:** a front-end forwards requests to different back-ends based on the Host (and may add its own host-related headers).

Beyond routing, applications often read the Host directly from server/request variables to **build absolute URLs** — links in pages and especially links inside emails (password resets, invites, verification).

## 2. Why this is a vulnerability class

Root cause: developers assume the Host header is not user-controllable. It is — any proxy/intercepting tool can set it to an arbitrary value. When the app or infra trusts that value for security-relevant decisions (link generation, routing, caching, access control), it becomes an injection/trust vector.

## 3. Override / manipulation techniques

Ways to influence the host value the app/infra actually uses:

1. **Arbitrary Host:** simply set `Host:` to an attacker value. First test — if the app still serves 200, validation is weak.
2. **Host override headers** — frequently honored by default even when `Host` is validated:
   - `X-Forwarded-Host` (most common)
   - `X-Host`
   - `X-Forwarded-Server`
   - `X-HTTP-Host-Override`
   - `Forwarded` (RFC 7239, `host=` directive)
3. **Duplicate Host headers:** send two `Host:` lines. Front-end and back-end may pick different ones (request smuggling-adjacent ambiguity), so a value rejected at the edge can reach the app.
4. **Absolute URL in the request line:** `GET https://attacker.example/path HTTP/1.1` plus a separate `Host:` line. RFC says the request line wins, but implementations differ — some route on the line, some on the header.
5. **Port injection:** `Host: legit.example:<payload>`. Validation that only checks the hostname portion may let the port carry an injection.
6. **Line wrapping / indentation:** a header line beginning with whitespace is treated as a continuation (obsolete folding). One parser folds it, another treats it as a new header, producing a front-end/back-end discrepancy.

Tooling: Burp Repeater for manual probing, Burp Intruder for vhost brute-forcing, Param Miner to discover supported override headers, Burp Collaborator / any OAST for out-of-band confirmation.

## 4. Exploitation vectors in depth

### 4.1 Password reset poisoning
Flow:
1. App builds the reset link from the Host (or an override header) when generating the reset email.
2. Attacker triggers a reset for the **victim's** account but injects their own host.
3. The victim receives an email whose link points to (or whose token leaks to) the attacker's domain.
4. Attacker obtains the reset token and takes over the account.

```
POST /forgot-password HTTP/1.1
Host: attacker.example
...
email=victim@example.com
```

Token-capture paths: victim clicks the attacker-host link (token in URL hits attacker server); or the legitimate page loads attacker-hosted resources and leaks the token via `Referer`; or the link host itself is attacker-controlled. Highest impact when the token reaches the attacker with no victim interaction.

### 4.2 Web cache poisoning
Goal: get a malicious, Host-derived value into a response that a cache stores under a key that other users will also request. Standalone caches usually include Host in the cache key (limiting this), so it is most viable when the application itself caches or when an override header is reflected but not keyed. Example payload reflected into the page:

```
GET /page HTTP/1.1
Host: vulnerable.example"><script>alert(1)</script>
```

If cached and served to other visitors, the reflected XSS executes for them.

### 4.3 Classic server-side injection via Host
If the Host value flows into a back-end sink unsanitized, the usual injection classes apply (SQLi, SSTI, command/RCE). Treat the Host like any other tainted input:

```
Host: vulnerable.example' OR '1'='1
```

### 4.4 Authentication / access-control bypass
Some apps restrict functionality to "internal" requests identified by Host or a host-based header. Spoofing the value can reach admin/internal-only routes:

```
GET /admin HTTP/1.1
Host: internal.company.local
```

or via `X-Forwarded-Host: internal.company.local` when the front-end forbids the raw Host.

### 4.5 Virtual host brute-forcing / internal websites
Internal sites may share the public server but have no public DNS. Keep the TCP connection to the public IP and vary the Host to enumerate them:

```
GET / HTTP/1.1
Host: intranet.example.com

GET / HTTP/1.1
Host: admin.example.com

GET / HTTP/1.1
Host: staging.example.com
```

Differing responses (status, length, content) reveal reachable internal vhosts. Burp Intruder over a subdomain wordlist automates this.

### 4.6 Routing-based SSRF
When the front-end routes upstream based on the Host header and does not validate it, point the Host at systems the front-end can reach but you cannot:

1. Confirm routing with OAST:
   ```
   GET / HTTP/1.1
   Host: <oast-id>.oast.example
   ```
   A DNS/HTTP hit at your OAST proves the front-end made the request.
2. Pivot to internal targets: cloud metadata `169.254.169.254`, `127.0.0.1`, and private ranges `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.

### 4.7 SSRF via malformed request line
Some custom proxies build the upstream URL by prepending a fixed backend to the request path. A crafted path can hijack the resulting URL:

```
GET @private-intranet/example HTTP/1.1
Host: public-domain.example
```

If the proxy forms `http://backend-server@private-intranet/example`, HTTP libraries read `backend-server` as userinfo and connect to `private-intranet`, bypassing the intended backend.

### 4.8 Connection-state attacks
If a server validates the Host only on the **first** request of a reused keep-alive connection and assumes subsequent requests share it, send a benign first request and a malicious second one on the same connection:

```
GET / HTTP/1.1
Host: legitimate.example

GET /admin HTTP/1.1
Host: attacker.example
```

The second request inherits the first request's validation, enabling routing-based SSRF or cache poisoning that per-request validation would have blocked.

## 5. Prevention
- Prefer relative URLs; never build absolute URLs from the Host header.
- When an absolute domain is required, take it from server-side configuration, not the request.
- Validate the incoming Host against an allowlist of permitted domains; reject or hard-fail otherwise.
- Explicitly disable / strip override headers (`X-Forwarded-Host`, `X-Host`, `Forwarded`, etc.) unless deliberately required.
- Configure load balancers / reverse proxies to only forward whitelisted hosts and to not trust client-supplied routing headers.
- Isolate internal virtual hosts from the public-facing infrastructure so routing tricks cannot reach them.
- Do not assume Host is constant across a reused connection; validate per request.
