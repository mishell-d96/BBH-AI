#!/usr/bin/env bash
# snapshot.sh <target> <outdir> [--i-have-confirmed-scope]
# Capture a point-in-time, scope-gated surface snapshot for diffing over time.
#
# Passive asset discovery (crt.sh, subfinder, DNS) is always safe. Live
# fingerprinting (httpx, crawl, JS fetch) is ACTIVE: it runs ONLY against
# in-scope hosts AND only when --i-have-confirmed-scope is passed.
#
# Scope is enforced by recon-mapper's scope_guard.py — the single source of
# scope truth. This script never reimplements scope logic.
#
# Note: -e is intentionally NOT set; a missing tool must not abort the snapshot.
# bash 3.2 compatible (no mapfile / associative arrays).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET="${1:?usage: snapshot.sh <target> <outdir> [--i-have-confirmed-scope]}"
OUTDIR="${2:?usage: snapshot.sh <target> <outdir> [--i-have-confirmed-scope]}"
GATE="${3:-}"

# scope dir defaults to the workspace ./scope (4 levels up from this script); override with SCOPE_DIR.
SCOPE_DIR="${SCOPE_DIR:-$HERE/../../../../scope}"
SCOPE_GUARD="$HERE/../../recon-mapper/scripts/scope_guard.py"
MAX_JS="${MAX_JS:-50}"

have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf '[snapshot] %s\n' "$*" >&2; }

if [ ! -f "$SCOPE_GUARD" ]; then
  log "FATAL: scope_guard.py not found at $SCOPE_GUARD — refusing (cannot verify scope)."
  exit 2
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
SNAP="$OUTDIR/snapshots/$TS"
RAW="$SNAP/raw"
mkdir -p "$RAW"

hashfile() {  # portable sha256 of a file -> hex
  if   have sha256sum; then sha256sum "$1" 2>/dev/null | awk '{print $1}'
  elif have shasum;    then shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  else echo "nohash"; fi
}

# ---------------------------------------------------------------------------
# 1. Passive subdomain discovery (always safe — public sources only)
# ---------------------------------------------------------------------------
: > "$RAW/hosts.txt"
printf '%s\n' "$TARGET" >> "$RAW/hosts.txt"

if have curl; then
  curl -fsS --max-time 60 "https://crt.sh/?q=%25.${TARGET}&output=json" -o "$RAW/crtsh.json" 2>/dev/null \
    && log "crt.sh ok" || log "crt.sh skipped (failed/rate-limited)"
else
  log "curl not installed — crt.sh skipped"
fi

if have subfinder; then
  subfinder -silent -d "$TARGET" >> "$RAW/hosts.txt" 2>/dev/null && log "subfinder ok" \
    || log "subfinder error"
else
  log "subfinder not installed — passive host set limited to crt.sh + apex"
fi

# fold crt.sh names into the host list
python3 - "$RAW/crtsh.json" "$RAW/hosts.txt" <<'PY' 2>/dev/null || true
import json, re, sys
src, dst = sys.argv[1:3]
try:
    data = json.load(open(src))
except Exception:
    data = []
names = set()
for row in data if isinstance(data, list) else []:
    for n in str(row.get("name_value", "")).splitlines():
        n = n.strip().lstrip("*.").lower().rstrip(".")
        if re.fullmatch(r"(?:[a-z0-9_-]+\.)+[a-z]{2,}", n):
            names.add(n)
with open(dst, "a") as f:
    for n in sorted(names):
        f.write(n + "\n")
PY
sort -u "$RAW/hosts.txt" -o "$RAW/hosts.txt"

# ---------------------------------------------------------------------------
# 2. SCOPE GATE — re-check EVERY discovered host before any active touch
# ---------------------------------------------------------------------------
TARGS=()
while IFS= read -r h; do
  [ -n "$h" ] && TARGS+=(--target "$h")
done < "$RAW/hosts.txt"

python3 "$SCOPE_GUARD" "${TARGS[@]}" \
    --scope-dir "$SCOPE_DIR" --in-scope "$TARGET" --in-scope "*.$TARGET" \
    --out "$SNAP/scope.json" >/dev/null 2>&1 || true

python3 - "$SNAP/scope.json" "$SNAP/inscope.txt" <<'PY'
import json, sys
try:
    sc = json.load(open(sys.argv[1]))
except Exception:
    sc = {}
ins = sorted({v["host"] for v in sc.get("verdicts", []) if v.get("in_scope")})
open(sys.argv[2], "w").write("\n".join(ins) + ("\n" if ins else ""))
print(f"[snapshot] {len(ins)} in-scope host(s) cleared for active probing", file=sys.stderr)
PY

# ---------------------------------------------------------------------------
# 3. Live fingerprint (ACTIVE — gated, in-scope hosts only)
# ---------------------------------------------------------------------------
if [ "$GATE" != "--i-have-confirmed-scope" ]; then
  log "passive snapshot only (no --i-have-confirmed-scope) — live state not captured."
else
  # httpx fingerprint
  if have httpx && [ -s "$SNAP/inscope.txt" ]; then
    httpx -silent -json -status-code -title -tech-detect -web-server -hash sha256 \
          -rate-limit 20 -l "$SNAP/inscope.txt" > "$RAW/httpx.jsonl" 2>/dev/null \
      && log "httpx ok" || log "httpx error"
  else
    log "httpx not installed or no in-scope hosts — live fingerprint skipped"
  fi

  # URL discovery (archive + crawl) over in-scope hosts
  : > "$RAW/urls.txt"
  if have gau; then
    while IFS= read -r h; do [ -n "$h" ] && gau "$h" 2>/dev/null; done < "$SNAP/inscope.txt" >> "$RAW/urls.txt"
    log "gau ok"
  elif have waybackurls; then
    while IFS= read -r h; do [ -n "$h" ] && printf '%s\n' "$h" | waybackurls 2>/dev/null; done < "$SNAP/inscope.txt" >> "$RAW/urls.txt"
    log "waybackurls ok"
  else
    log "gau/waybackurls not installed — archive URLs skipped"
  fi
  if have katana && [ -s "$SNAP/inscope.txt" ]; then
    katana -silent -jc -rate-limit 20 -d 2 -list "$SNAP/inscope.txt" >> "$RAW/urls.txt" 2>/dev/null && log "katana ok" \
      || log "katana error"
  fi
  sort -u "$RAW/urls.txt" -o "$RAW/urls.txt" 2>/dev/null || true

  # JavaScript bundles -> fetch + hash (capped; in-scope hosts only)
  grep -iE '\.js($|\?)' "$RAW/urls.txt" 2>/dev/null | sort -u > "$RAW/js_urls.txt" || : > "$RAW/js_urls.txt"
  JS_TOTAL=$(wc -l < "$RAW/js_urls.txt" 2>/dev/null | tr -d ' '); JS_TOTAL="${JS_TOTAL:-0}"
  : > "$RAW/js_hashes.jsonl"
  n=0
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    n=$((n + 1)); [ "$n" -gt "$MAX_JS" ] && break
    host=$(printf '%s' "$u" | sed -E 's#^[a-zA-Z]+://([^/]+).*#\1#' | sed -E 's#:.*##')
    grep -qx "$host" "$SNAP/inscope.txt" || continue   # never fetch from an out-of-scope host
    tmp="$RAW/.js_fetch.tmp"
    if have curl && curl -fsS --max-time 20 "$u" -o "$tmp" 2>/dev/null; then
      h=$(hashfile "$tmp"); bytes=$(wc -c < "$tmp" 2>/dev/null | tr -d ' ')
      python3 - "$u" "$h" "${bytes:-0}" "$RAW/js_hashes.jsonl" <<'PY' 2>/dev/null || true
import json, sys
url, h, b, path = sys.argv[1:5]
open(path, "a").write(json.dumps({"url": url, "hash": h, "bytes": int(b)}) + "\n")
PY
      rm -f "$tmp"
    fi
  done < "$RAW/js_urls.txt"
  if [ "$JS_TOTAL" -gt "$MAX_JS" ]; then
    log "JS fetch capped at $MAX_JS of $JS_TOTAL (raise MAX_JS to cover more) — recorded in surface.json"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Assemble surface.json
# ---------------------------------------------------------------------------
python3 - "$SNAP" "$TARGET" "$TS" "$MAX_JS" <<'PY'
import json, os, re, sys
snap, target, ts, maxjs = sys.argv[1:5]
raw = os.path.join(snap, "raw")

def lines(p):
    return [l.strip() for l in open(p)] if os.path.exists(p) else []

hosts = {}
hp = os.path.join(raw, "httpx.jsonl")
if os.path.exists(hp):
    for line in open(hp):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        host = d.get("input") or d.get("host") or d.get("url") or ""
        host = re.sub(r"^[a-zA-Z]+://", "", host).split("/")[0].split(":")[0].lower()
        bh = d.get("hash")
        if isinstance(bh, dict):
            bh = bh.get("body_sha256") or bh.get("body_md5")
        hosts[host] = {
            "status": d.get("status_code"),
            "title": d.get("title"),
            "tech": sorted(d.get("tech", []) or []),
            "server": d.get("webserver"),
            "body_hash": bh,
        }

# every in-scope host appears, even if not live (status stays null)
for h in lines(os.path.join(snap, "inscope.txt")):
    if h:
        hosts.setdefault(h, {"status": None, "title": None, "tech": [], "server": None, "body_hash": None})

endpoints = sorted({u for u in lines(os.path.join(raw, "urls.txt")) if u})

js = []
jp = os.path.join(raw, "js_hashes.jsonl")
if os.path.exists(jp):
    for line in open(jp):
        try:
            js.append(json.loads(line))
        except Exception:
            pass
js_total = len(lines(os.path.join(raw, "js_urls.txt")))

surface = {
    "target": target,
    "ts": ts,
    "hosts": hosts,
    "endpoints": endpoints,
    "js": sorted(js, key=lambda x: x["url"]),
    "js_total_seen": js_total,
    "js_hashed": len(js),
    "js_cap": int(maxjs),
}
json.dump(surface, open(os.path.join(snap, "surface.json"), "w"), indent=2)
print(f"[snapshot] {ts}: {len(hosts)} hosts, {len(endpoints)} endpoints, "
      f"{len(js)}/{js_total} JS hashed", file=sys.stderr)
PY

# update the LATEST pointer
mkdir -p "$OUTDIR/snapshots"
printf '%s\n' "$TS" > "$OUTDIR/snapshots/LATEST"
log "snapshot written -> $SNAP/surface.json"
printf '%s\n' "$SNAP/surface.json"
