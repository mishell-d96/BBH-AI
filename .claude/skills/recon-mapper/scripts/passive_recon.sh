#!/usr/bin/env bash
# passive_recon.sh <target> <outdir> — Phase 1: public-source asset discovery only.
# NO intrusive contact with the target's own services. Degrades gracefully.
# Note: -e is intentionally NOT set; a missing tool must not abort the phase.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/_lib.sh"

TARGET="${1:?usage: passive_recon.sh <target> <outdir>}"
OUTDIR="${2:?usage: passive_recon.sh <target> <outdir>}"
export OUTDIR
RAW="$OUTDIR/raw"
mkdir -p "$RAW"

if done_already phase1_passive; then
  echo "[passive] phase1 already done (set FORCE=1 to rerun)" >&2; exit 0
fi
set_phase phase1_passive running

# --- Certificate transparency (crt.sh) ---
if have curl; then
  if curl -fsS --max-time 60 "https://crt.sh/?q=%25.${TARGET}&output=json" -o "$RAW/crtsh.json" 2>/dev/null; then
    note_tool crt.sh ok
  else
    note_tool crt.sh skipped "request failed or rate-limited"
  fi
else
  note_tool curl skipped "not installed"
fi

# --- Passive subdomain enumeration ---
if have subfinder; then
  subfinder -silent -d "$TARGET" >"$RAW/subfinder.txt" 2>/dev/null && note_tool subfinder ok \
    || note_tool subfinder skipped "error"
else
  note_tool subfinder skipped "not installed"
fi

# --- DNS records ---
if have dig; then
  { for rt in A AAAA CNAME MX TXT NS SOA; do
      echo "; $rt"; dig +short "$rt" "$TARGET" 2>/dev/null
    done; } >"$RAW/dns.txt" && note_tool dig ok
else
  note_tool dig skipped "not installed"
fi

# --- WHOIS ownership context ---
if have whois; then
  whois "$TARGET" >"$RAW/whois.txt" 2>/dev/null && note_tool whois ok || note_tool whois skipped "error"
else
  note_tool whois skipped "not installed"
fi

# --- Archived URLs (historical surface) ---
# waybackurls/gau are accelerators if present; otherwise query the Wayback CDX API directly (curl only).
if have waybackurls; then
  echo "$TARGET" | waybackurls >"$RAW/archive_urls.txt" 2>/dev/null && note_tool waybackurls ok
elif have gau; then
  gau --subs "$TARGET" >"$RAW/archive_urls.txt" 2>/dev/null && note_tool gau ok
elif have curl; then
  if curl -fsS --max-time 60 \
       "https://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey&limit=5000" \
       -o "$RAW/archive_urls.txt" 2>/dev/null; then
    note_tool "wayback-cdx" ok "curl fallback (waybackurls/gau absent)"
  else
    note_tool "wayback-cdx" skipped "request failed or rate-limited"
  fi
else
  note_tool waybackurls skipped "not installed (gau and curl also absent)"
fi

# --- Assemble phase1_assets.json (dedupe hosts from all passive sources) ---
python3 - "$TARGET" "$OUTDIR" <<'PY'
import json, os, re, sys
target, outdir = sys.argv[1:3]
raw = os.path.join(outdir, "raw")
hosts = {}  # host -> set(sources)

def add(h, src):
    h = h.strip().lower().rstrip(".")
    if h and re.fullmatch(r"(?:[a-z0-9_-]+\.)+[a-z]{2,}", h):
        hosts.setdefault(h, set()).add(src)

# crt.sh
p = os.path.join(raw, "crtsh.json")
if os.path.exists(p):
    try:
        data = json.load(open(p))
        for row in data:
            for name in str(row.get("name_value", "")).splitlines():
                add(name.lstrip("*."), "crt.sh")
    except Exception:
        pass
# subfinder
p = os.path.join(raw, "subfinder.txt")
if os.path.exists(p):
    for line in open(p):
        add(line, "subfinder")
# archived urls -> hostnames
p = os.path.join(raw, "archive_urls.txt")
if os.path.exists(p):
    for line in open(p):
        m = re.search(r"https?://([^/\s:]+)", line)
        if m:
            add(m.group(1), "archive")

assets = {
    "target": target,
    "hosts": [{"host": h, "sources": sorted(s), "in_scope": None} for h, s in sorted(hosts.items())],
    "whois_file": "raw/whois.txt" if os.path.exists(os.path.join(raw, "whois.txt")) else None,
    "dns_file": "raw/dns.txt" if os.path.exists(os.path.join(raw, "dns.txt")) else None,
    "note": "Re-run scope_guard.py over every host; set in_scope and drop out-of-scope to scope.json.excluded.",
}
json.dump(assets, open(os.path.join(outdir, "phase1_assets.json"), "w"), indent=2)
print(f"[passive] {len(hosts)} unique host(s) discovered", file=sys.stderr)
PY

set_phase phase1_passive done
echo "[passive] phase 1 complete -> $OUTDIR/phase1_assets.json" >&2
