# Tooling Install Log

Every tool I install in beta mode is recorded here (date, tool, version, purpose, install path, exact
command). Standard Kali tools that ship preinstalled are **not** logged — only additions. Installing a
tool never widens scope: SCOPE GATE and rate limits still bind.

## Preinstalled baseline (verified present 2026-06-05, not installed by me)
`curl jq nmap ffuf gobuster sqlmap nuclei httpx subfinder amass nikto wpscan dig wfuzz` —
plus toolchains `pipx`, `pip3`, `go 1.26.3`, `apt`.

## Installations

| Date | Tool | Version | Purpose | Path | Install command |
|------|------|---------|---------|------|-----------------|
| 2026-06-05 | arjun | 2.2.7 | HTTP **parameter discovery** — surface hidden/undocumented params on endpoints (mass-assignment, IDOR, injection leads). Generally applicable to any web/API target. | `~/.local/bin/arjun` | `pipx install arjun` |
| 2026-06-05 | dalfox | latest (go install) | **XSS automation** — fast reflected/DOM XSS verification to support (not replace) manual testing of reflected/stored sinks. | `~/go/bin/dalfox` | `GOFLAGS=-mod=mod go install github.com/hahwul/dalfox/v2@latest` |
| 2026-06-05 | katana | latest (go install) | Fast **crawler** — endpoint/JS discovery to feed recon-mapper Phase 2 (the SKILL already references it; now actually present). | `~/go/bin/katana` | `GOFLAGS=-mod=mod go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| 2026-06-05 | interactsh-client | latest (go install) | **OAST callback channel** — the actionable way to turn blind SSRF/SQLi/OS-cmd/XXE/SSTI into jitter-immune binary proof (DNS+HTTP callbacks). Five blind-capable skills referenced OAST abstractly with no way to get a host; now `interactsh-client -v` gives a live domain (public `oast.fun`/`oast.pro` as zero-install fallback). | `~/go/bin/interactsh-client` | `GOFLAGS=-mod=mod go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| 2026-06-05 | jwt_tool | git (ticarpi) | **Standard-JWT attack scanner** — one-command none/alg-confusion/kid/jku/weak-secret first pass before manual confirmation. Not on PyPI, so git-clone + symlink. (Does nothing for opaque/non-JWT tokens — that's the new `custom-opaque-tokens` skill.) | `~/.local/bin/jwt_tool` → `~/tools/jwt_tool/jwt_tool.py` | `git clone https://github.com/ticarpi/jwt_tool ~/tools/jwt_tool && pip3 install --user --break-system-packages -r requirements.txt` |
| 2026-06-05 | x8 | latest (cargo) | **Behavior-changing parameter discovery** — beats arjun for the mass-assignment/hidden-flag class (finds non-*reflecting* params by response-diffing), the exact class behind broken-authz/priv-esc. | `~/.cargo/bin/x8` | `cargo install x8` |

## PATH notes
- `~/.local/bin` is already on PATH via `~/.zshrc` (arjun, jwt_tool work directly).
- `~/go/bin` (Go tools: dalfox, katana, interactsh-client) and `~/.cargo/bin` (x8) were **added to
  `~/.zshrc`** on 2026-06-05 (`export PATH="$PATH:$HOME/go/bin"` and `...:$HOME/.cargo/bin`).
- **Subagent-shell caveat (observed):** workflow subagents sometimes start with an empty/broken `PATH`
  and `export PATH=...` does not persist between their Bash calls (each re-sources a profile). When
  driving tools from inside a workflow agent, prepend `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin` at the top of **every** command, or call binaries by absolute path.

## Why these three (signal over noise)
Chosen against real friction, not for completeness. The target this session was an API-heavy app with
untested reflected/stored-XSS and hidden-parameter candidates; `arjun` + `dalfox` directly accelerate
those, and `katana` was already named in `recon-mapper` but missing. No scanners installed that would
only add raw, manual-validation-required noise.
