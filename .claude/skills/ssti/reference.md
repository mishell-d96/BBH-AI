# SSTI Reference

Comprehensive reference for Server-Side Template Injection. Companion to `SKILL.md` (lean playbook) and `cheatsheet.md` (per-engine payloads).

Primary sources:
- https://portswigger.net/web-security/server-side-template-injection
- https://portswigger.net/web-security/server-side-template-injection/exploiting

---

## 1. What it is

Server-side template injection occurs when an attacker can inject native template
syntax into a template that is then rendered server-side. Template engines render
templates by combining a static template with dynamic data. SSTI arises when user
input is concatenated *into the template itself* rather than passed in as *data* —
so the engine evaluates attacker-controlled syntax.

This differs from XSS, where the payload executes in the victim's browser. With SSTI
the payload executes on the server, inside the template engine's context, which
commonly leads to remote code execution and full server compromise.

Common root cause: developers intentionally let users supply or edit templates (e.g.
customizable email/marketing content), or they unsafely build a template string by
concatenating user input, e.g. (Python):
`render_template_string("Hello " + name)` instead of passing `name` as a parameter.

---

## 2. Impact

Per PortSwigger, consequences range from catastrophic to moderate:
- **Catastrophic:** remote code execution → complete control of the backend server.
- **High (sandboxed/no RCE):** arbitrary file read, reading sensitive data, leaking
  environment variables, secrets, and configuration.
- **Lower:** information disclosure or limited expression evaluation with no reachable
  sink. Frame these honestly.

---

## 3. Detection methodology

### 3.1 Initial fuzzing
Inject the polyglot set of characters used across template expression syntaxes:

```
${{<%[%'"}}%\
```

Any resulting exception / template error is a strong signal of SSTI and frequently
discloses the engine in a stack trace. Lack of an error does not rule it out.

### 3.2 Identify the context (PortSwigger decision tree)

SSTI lands in one of two contexts. Detecting it requires different probes per context.

**Plaintext context.** Input appears in template text as free data, e.g. a template
of the form `Hello {{name}}` where you control `name`, or `render("Hello " + input)`.
Here you can supply arbitrary expressions. Probe with a math operation:

```
http://vulnerable-website.com/?username=${7*7}
```

If the response renders `Hello 49`, the expression was evaluated server-side → SSTI.
Try multiple syntaxes since the engine is unknown: `${7*7}`, `{{7*7}}`, `${{7*7}}`,
`<%= 7*7 %>`, `#{7*7}`.

**Code context.** Input is placed *inside* an existing template expression, e.g.:
```
greeting = getQueryParameter('greeting')
engine.render("Hello {{ " + greeting + " }}", data)
```
with a request like `?greeting=data.username`. A bare `7*7` here may evaluate
regardless and proves nothing. Method:
1. First inject benign HTML such as `<p>` to confirm whether output is just reflected
   (potential XSS, not SSTI).
2. Then attempt to break out of the expression and inject template syntax of your own:
   ```
   http://vulnerable-website.com/?greeting=data.username}}<tag>
   ```
   If `Hello` (the static prefix) renders, the `<tag>` HTML appears, and the breakout
   does not throw, you likely have SSTI in a code context.

### 3.3 Identify the engine

Once SSTI is confirmed, fingerprint the engine — exploitation is engine-specific.

- **Invalid syntax → read the error.** Submitting malformed expressions usually
  surfaces an engine-named exception.
- **Behavioral probes.** The classic disambiguation:
  - `{{7*7}}` → `49` means a `{{ }}` engine (Jinja2, Twig, Handlebars, ...).
  - `${7*7}` → `49` means a `${ }` engine (Freemarker, Velocity, JSP EL, Smarty).
  - `<%= 7*7 %>` → `49` means ERB / EJS / ASP-style.
  - `#{7*7}` → `49` suggests Pug/Jade or Thymeleaf.
  - **`{{7*'7'}}`**: `49` → **Twig** (PHP coerces); `7777777` → **Jinja2** (Python
    string repetition). This single probe separates the two most common `{{ }}` engines.
- See `cheatsheet.md` for per-engine fingerprint probes.

Build a mental decision tree: send a candidate set, observe which renders, then narrow.

---

## 4. Exploitation methodology

PortSwigger's three-step approach: **Read → Explore → Create.**

### 4.1 Read — documentation & known exploits
- Study the engine's official template syntax docs. Often RCE is "as simple as" using
  a native code block the engine intentionally supports.
- Read the engine's **security documentation** — its list of "dangerous" features /
  built-ins to avoid is effectively an exploitation roadmap.
- Search for known SSTI exploit payloads for that engine (and version).

Examples of direct code execution where the engine permits code blocks:
- **Mako (Python):** `<% import os x=os.popen('id').read() %>${x}`
- **ERB (Ruby):** `<%= Dir.entries('/') %>` and `<%= File.open('/path/file').read %>`

### 4.2 Explore — the environment & objects
Even without an obvious code block, engines expose objects you can walk.
- Many engines expose a `self` / environment object enumerating accessible
  attributes and methods.
- **Java example:** `${T(java.lang.System).getenv()}` lists environment variables.
- **Developer-supplied objects** are especially valuable — custom objects injected
  into the template context often hold secrets or expose exploitable methods
  (DB handles, file helpers, HTTP clients).

### 4.3 Create — construct the attack
When no off-the-shelf payload works, chain discovered objects/methods.
- **Object chaining (Velocity/Java):**
  `$class.inspect("java.lang.Runtime").type.getRuntime().exec("bad-stuff-here")`
  (use harmless commands when proving).
- In sandboxed engines where built-in RCE is blocked, pivot through developer-supplied
  objects to achieve file traversal or data exfiltration instead of code execution.

---

## 5. Developer vs non-developer scenarios

- **Non-developer (unintended) SSTI:** input that should be *data* is concatenated
  into the template (the "Hello " + name bug). The user never meant to write templates;
  you are abusing an injection flaw. Usually the highest-value, least-restricted case.
- **Developer / intended templating:** the app legitimately lets users author templates
  (email builders, theming, report designers). The engine may be **sandboxed** to block
  dangerous features. Here exploitation focuses on sandbox escape or abusing whatever
  objects/filters the sandbox still exposes. Read the sandbox config and its known
  bypasses.

---

## 6. Reading sensitive data & files (when RCE is blocked)

Still high impact without command execution:
- Enumerate environment variables (`getenv`, settings/config objects) for secrets,
  API keys, DB credentials.
- Read files via engine file APIs (`File.open(...).read` in ERB, `os.popen('cat ...')`
  via globals in Jinja2, `freemarker.template.utility.Execute`, etc.).
- Dump the template context / config object (e.g. Jinja2 `{{ config }}`, Flask
  `{{ config.items() }}`) which often contains `SECRET_KEY` and DB URIs.

---

## 7. Verification discipline (this workspace)

- Prove RCE with **harmless** commands only: `id`, `hostname`, `whoami`, `uname -a`,
  `cat /etc/hostname`. Never write, delete, modify, or exfiltrate beyond what is needed
  to prove impact.
- Strict scope gate: confirm the target host/asset is in scope before sending payloads.
- Minimal safe PoC: the smallest request that demonstrates evaluation, plus the smallest
  that demonstrates real impact (command output / file contents / leaked secret).
- Log proven findings to `./_EXPLOIT/` with a minimal curl repro (see `SKILL.md`).

---

## 8. Prevention (for triage notes / reporting recommendations)

- Don't let users supply or edit raw templates where avoidable.
- Pass user input as **data/parameters**, never concatenate it into template source.
- If user templates are required, use a **logic-less** engine (e.g. Mustache) or run
  rendering in a locked-down sandbox in an isolated, low-privilege Docker container with
  no network and minimal filesystem access.
- Keep template engines patched; sandboxes have historically been bypassed.

---

## 9. References
- https://portswigger.net/web-security/server-side-template-injection
- https://portswigger.net/web-security/server-side-template-injection/exploiting
- Engine fingerprints & full payloads: `cheatsheet.md`
