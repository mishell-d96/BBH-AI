# Prototype Pollution — Deep Reference

Sources:
- https://portswigger.net/web-security/prototype-pollution
- https://portswigger.net/web-security/prototype-pollution/client-side
- https://portswigger.net/web-security/prototype-pollution/server-side

---

## 1. JavaScript prototypes & inheritance

Almost every JS object is linked to a **prototype** object. When you read a property,
the engine checks the object itself, then walks the **prototype chain** (object ->
its prototype -> that prototype's prototype -> ... -> `Object.prototype` -> `null`)
until found. Inherited properties (including methods) come from these prototypes.

- Object literals `{}` inherit from `Object.prototype`.
- Each object exposes its prototype via the accessor `__proto__` (a getter/setter on
  `Object.prototype`). So `obj.__proto__ === Object.getPrototypeOf(obj)`.
- A constructor function exposes the shared prototype as `Constructor.prototype`, and
  instances reach it via `instance.constructor.prototype`. Hence
  `({}).constructor.prototype === Object.prototype` — this is why `constructor` is an
  alternate route to the same prototype as `__proto__`.

**Why it matters:** if you can write to `Object.prototype`, the property is inherited
by *every* plain object that does not define that property itself.

---

## 2. How pollution arises

### Unsafe recursive merge
The classic bug. App merges a user-controlled object into a target without
sanitizing keys:

```js
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && typeof target[key] === 'object') {
      merge(target[key], source[key]);          // recurse
    } else {
      target[key] = source[key];                 // assign
    }
  }
  return target;
}
```

When `source` is `{"__proto__": {"evil": "x"}}`, the recursion enters
`target.__proto__` — which **is** `Object.prototype` — and assigns `evil` onto it.
Now `({}).evil === "x"` globally. Libraries historically affected: lodash `merge`/
`defaultsDeep`, jQuery `$.extend(true, …)`, many home-grown deep-merge/clone utils,
and query-string parsers that build nested objects from bracketed keys.

### Direct property assignment from nested input
Query/path parsers that turn `a[b][c]=d` into `{a:{b:{c:'d'}}}` can be driven with
`__proto__[evil]=x` to set a prototype property directly.

### Required components
1. **Source** — controllable input that reaches the prototype (URL query, URL
   hash/fragment, JSON body, form data).
2. **Sink** — a dangerous function/DOM property (`eval`, `Function`, `setTimeout`
   string form, `innerHTML`, script `src`, `child_process.*`).
3. **Gadget** — a property the app/library reads and passes to a sink unsafely; you
   control its value through the polluted prototype.

No gadget reaching a sink = no impact (see SKILL.md "Don't report as noise").

---

## 3. Sources

- **URL query string:** `?__proto__[foo]=bar` (and `?constructor[prototype][foo]=bar`).
- **URL fragment/hash:** parsed client-side by routers/SPAs.
- **JSON request body:** `{"__proto__":{"foo":"bar"}}` parsed straight into objects.
- **Other deserialized input:** form-encoded nested keys, YAML, etc.

---

## 4. Client-side prototype pollution

### Finding sources manually
- Append a unique marker to candidate inputs:
  `vulnerable-website.com/?__proto__[ppmarker]=1`
- In DevTools console check: `Object.prototype.ppmarker` -> if it returns `1`,
  the source pollutes the global prototype.
- Repeat with `constructor[prototype][ppmarker]=1` and with JSON/hash inputs.

### Finding sources with DOM Invader
Burp's browser has **DOM Invader** with a prototype-pollution mode that browses and
auto-tests sources for you, then can **auto-generate a DOM XSS PoC** for some gadgets.
Far faster than manual fuzzing.

### Finding gadgets manually
1. Identify properties read by the app or its libraries (config-like option names).
2. In Burp, intercept the relevant script response and inject a `debugger;` statement.
3. Set a logging trap on the suspected property:
   ```js
   Object.defineProperty(Object.prototype, 'PROPERTY', {
     get() { console.trace(); return 'polluted'; }
   });
   ```
4. Reload; when the property is read, the stack trace shows whether it flows to a
   sink (e.g. `innerHTML`, `eval`, script-element `src`).

### Finding gadgets with DOM Invader
DOM Invader scans for gadgets automatically and may emit a working PoC.

### Gadget -> DOM XSS
Pollute a property a script loader or HTML sink consumes. Canonical example: a loader
that builds a script URL from a config property:
```
https://vulnerable-website.com/?__proto__[transport_url]=data:,alert(1);//
```
Other shapes: polluting an `src`/`url` option, or a sanitizer-config flag so HTML is
inserted unsanitized into `innerHTML`.

### Browser API gadgets
Native browser APIs contain widely-reusable gadgets, so a single pollution source can
yield XSS even when the app's own code looks clean. Treat any pollution source on a
modern browser as potentially exploitable via these.

---

## 5. Server-side prototype pollution

Harder to detect (no console). Look for **observable side effects** of polluting
`Object.prototype`. All probes below are non-destructive.

### Detection — property reflection
Many handlers iterate with `for...in`, which includes inherited enumerable props.
Send `{"__proto__":{"foo":"bar"}}`; if `foo` shows up in a JSON response object it
didn't have before, the prototype is polluted.

### Detection — status-code override
Node's `http-errors` reads `status`/`statusCode` from error objects. Pollute it to an
unusual code in 400–599 (e.g. `{"__proto__":{"status":510}}`), then trigger an error
path; a changed status confirms pollution.

### Detection — JSON spacing
Express reads a `json spaces` setting when serializing. Pollute
`{"__proto__":{"json spaces":10}}`; an unpatched app re-indents JSON responses —
visible whitespace change confirms pollution without needing reflection.

### Detection — charset override
`getCharset()` falls back to empty when no charset is set. Pollute `content-type`
with a UTF-7 charset; then a UTF-7-encoded string (e.g. `+AGYAbwBv-` for `foo`) will
be decoded in the response if pollution worked.

### Exploiting to RCE
Server-side gadgets typically poison **options consumed by a later
`child_process` call**.

- **`child_process.fork()` via `execArgv` / `NODE_OPTIONS`:** controlling the args
  array lets you inject `--eval`/`--inspect`. To *detect* a spawnable, controllable
  child process safely, use OAST:
  ```json
  {"__proto__":{"argv0":"node","shell":"node","NODE_OPTIONS":"--inspect=YOUR-ID.oastify.com"}}
  ```
  A Collaborator/OAST hit when the app spawns a child = controllable spawn -> RCE.
- **`child_process.execSync()` via `shell` + `input`:** pollute the spawn options so
  the command is fed through stdin. Using an interactive shell that reads stdin (e.g.
  `vim`) sidesteps arg limits:
  ```json
  {"__proto__":{"shell":"vim","input":":! <command>\n"}}
  ```
  Use `<command>` as a benign OAST callback or fixed-duration sleep for safe proof —
  never a destructive command.
- **`execArgv` array injection (fork):** `{"__proto__":{"execArgv":["--eval=<js>"]}}`
  to run JS in the forked child.

### Bypassing input filters
- **`constructor.prototype` instead of `__proto__`:** `?constructor[prototype][x]=y`
  or `{"constructor":{"prototype":{"x":"y"}}}` — same destination, dodges `__proto__`
  blacklists.
- **Single-pass key stripping:** if the filter removes `__proto__` once and
  non-recursively, `__pro__proto__to__` collapses back to `__proto__`.
- **Encoding/obfuscation** of the blocked keyword where the parser normalizes it.

---

## 6. Prevention (for triage write-ups / remediation advice)

- **Sanitize keys** before merging: reject/skip `__proto__`, `constructor`,
  `prototype`. Recursively/iteratively, not single-pass.
- **`Object.freeze(Object.prototype)`** to block writes to the global prototype.
- **Null-prototype objects:** `Object.create(null)` for maps/config so there is no
  prototype to pollute.
- **Use `Map`** instead of plain objects for arbitrary key/value stores.
- **Schema validation** (JSON Schema, allow-listed keys/types) on all parsed input.
- Prefer library APIs/versions that are hardened against `__proto__` keys.
