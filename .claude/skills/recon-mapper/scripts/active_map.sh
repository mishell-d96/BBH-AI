#!/usr/bin/env bash
# active_map.sh <outdir> --i-have-confirmed-scope — Phase 2: active mapping of IN-SCOPE hosts.
# Refuses without the explicit gate flag. Conservative rates. Degrades gracefully.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/_lib.sh"

OUTDIR="${1:?usage: active_map.sh <outdir> --i-have-confirmed-scope}"
export OUTDIR
shift || true
GATE=0
for a in "$@"; do [ "$a" = "--i-have-confirmed-scope" ] && GATE=1; done
if [ "$GATE" -ne 1 ]; then
  echo "[active_map] REFUSING: confirm scope.json, then pass --i-have-confirmed-scope." >&2
  exit 4
fi

RAW="$OUTDIR/raw"; mkdir -p "$RAW"
HOSTS="$RAW/inscope_hosts.txt"

# Derive the in-scope host list: prefer scope.json verdicts, else phase1 assets marked in_scope.
python3 - "$OUTDIR" <<'PY' >"$HOSTS"
import json, os, sys
outdir = sys.argv[1]
hosts = []
sp = os.path.join(outdir, "scope.json")
if os.path.exists(sp):
    try:
        sj = json.load(open(sp))
        hosts = [v["host"] for v in sj.get("verdicts", []) if v.get("in_scope")]
    except Exception:
        hosts = []
if not hosts:
    ap = os.path.join(outdir, "phase1_assets.json")
    if os.path.exists(ap):
        try:
            aj = json.load(open(ap))
            hosts = [h["host"] for h in aj.get("hosts", []) if h.get("in_scope") is True]
        except Exception:
            hosts = []
for h in sorted(set(hosts)):
    print(h)
PY

if [ ! -s "$HOSTS" ]; then
  echo "[active_map] no confirmed in-scope hosts (scope.json verdicts / phase1 in_scope=true). Aborting." >&2
  exit 5
fi
echo "[active_map] $(wc -l <"$HOSTS" | tr -d ' ') in-scope host(s)" >&2

if done_already phase2_active; then
  echo "[active_map] phase2 already done (set FORCE=1 to rerun)" >&2; exit 0
fi
set_phase phase2_active running

# --- Live host probing + fingerprint (rate-limited) ---
if have httpx; then
  httpx -silent -json -rate-limit 20 -timeout 10 -title -tech-detect -status-code -tls-grab \
        -list "$HOSTS" >"$RAW/httpx.jsonl" 2>/dev/null && note_tool httpx ok \
        || note_tool httpx skipped "error"
else
  note_tool httpx skipped "not installed"
fi

# --- Port/service detection (polite timing, top ports) ---
if have nmap; then
  nmap -iL "$HOSTS" -Pn -T2 --top-ports 100 -sV --max-rate 50 -oX "$RAW/nmap.xml" >/dev/null 2>&1 \
    && note_tool nmap ok || note_tool nmap skipped "error"
else
  note_tool nmap skipped "not installed"
fi

# --- Crawl / spider (links + JS) ---
if have katana; then
  katana -silent -list "$HOSTS" -jc -d 3 -rate-limit 20 >"$RAW/crawl.txt" 2>/dev/null && note_tool katana ok \
    || note_tool katana skipped "error"
elif have gospider; then
  gospider -S "$HOSTS" -q -d 3 -t 5 >"$RAW/crawl.txt" 2>/dev/null && note_tool gospider ok \
    || note_tool gospider skipped "error"
else
  note_tool katana skipped "not installed (gospider also absent)"
fi

# --- Content discovery (throttled, needs a wordlist) ---
WL="${FFUF_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
if have ffuf && [ -f "$WL" ]; then
  : >"$RAW/ffuf.jsonl"
  while read -r h; do
    [ -z "$h" ] && continue
    ffuf -u "https://${h}/FUZZ" -w "$WL" -rate 20 -t 10 -mc 200,204,301,302,307,401,403 \
         -of json -o "$RAW/ffuf_${h}.json" -s >/dev/null 2>&1 && echo "$RAW/ffuf_${h}.json" >>"$RAW/ffuf.jsonl"
  done <"$HOSTS"
  note_tool ffuf ok
else
  note_tool ffuf skipped "missing tool or wordlist ($WL)"
fi

# --- Low-noise nuclei (exposures/misconfig/tech only — NOT intrusive fuzzing) ---
if have nuclei; then
  nuclei -silent -list "$HOSTS" -tags exposure,misconfiguration,tech -rate-limit 20 \
         -jsonl -o "$RAW/nuclei.jsonl" >/dev/null 2>&1 && note_tool nuclei ok \
         || note_tool nuclei skipped "error"
else
  note_tool nuclei skipped "not installed"
fi

# --- Assemble phase2_surface.json ---
python3 - "$OUTDIR" <<'PY'
import json, os, re, sys
outdir = sys.argv[1]
raw = os.path.join(outdir, "raw")

hosts = []
hp = os.path.join(raw, "httpx.jsonl")
if os.path.exists(hp):
    for line in open(hp):
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        hosts.append({
            "host": j.get("input") or j.get("host") or j.get("url"),
            "url": j.get("url"),
            "status": j.get("status_code") or j.get("status-code"),
            "title": j.get("title"),
            "tech": j.get("tech") or j.get("technologies") or [],
            "webserver": j.get("webserver"),
        })

endpoints = set()
cp = os.path.join(raw, "crawl.txt")
if os.path.exists(cp):
    for line in open(cp):
        u = line.strip()
        if u.startswith("http"):
            endpoints.add(u)
ap = os.path.join(raw, "archive_urls.txt")
if os.path.exists(ap):
    for line in open(ap):
        u = line.strip()
        if u.startswith("http"):
            endpoints.add(u)

js_files = sorted({u for u in endpoints if u.split("?")[0].endswith(".js")})
endpoint_objs = [{"url": u, "methods": ["GET"], "params": [], "source": "crawl/archive"}
                 for u in sorted(endpoints)]

surface = {
    "hosts": hosts,
    "endpoints": endpoint_objs,
    "js_files": js_files,
    "secrets_leads": [],
    "auth_surface": sorted({u for u in endpoints
                            if re.search(r"/(login|signin|signup|register|reset|password|oauth|sso|token|auth)\b", u, re.I)}),
    "manual_supplement_required": [
        "forms-based navigation (one URL, many actions by body param)",
        "multi-stage flows (checkout/KYC/wizards needing prior state)",
        "JS-driven menus / SPA routes not in crawlable hrefs",
        "volatile/anti-CSRF params that break naive replay",
        "authenticated areas (recrawl per role with valid sessions)",
    ],
}
json.dump(surface, open(os.path.join(outdir, "phase2_surface.json"), "w"), indent=2)
print(f"[active] {len(hosts)} host record(s), {len(endpoint_objs)} endpoint(s)", file=sys.stderr)
PY

set_phase phase2_active done
echo "[active_map] phase 2 complete -> $OUTDIR/phase2_surface.json" >&2
echo "[active_map] REMINDER: spidering is incomplete — supplement manually via Burp (see surface.manual_supplement_required)." >&2
