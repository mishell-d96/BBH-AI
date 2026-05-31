#!/usr/bin/env bash
# Shared helpers for recon-mapper shell scripts. Source this: `source _lib.sh`.
# Requires: python3 (guaranteed), bash. $OUTDIR must be exported by the caller.

# have TOOL -> 0 if TOOL is on PATH
have() { command -v "$1" >/dev/null 2>&1; }

# note_tool NAME STATUS [REASON]  -> append a record to $OUTDIR/raw/tools.jsonl + stderr line
note_tool() {
  local name="$1" status="$2" reason="${3:-}"
  mkdir -p "$OUTDIR/raw" 2>/dev/null || true
  python3 - "$name" "$status" "$reason" "$OUTDIR/raw/tools.jsonl" <<'PY' 2>/dev/null || true
import json, sys
name, status, reason, path = sys.argv[1:5]
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps({"tool": name, "status": status, "reason": reason}) + "\n")
PY
  printf '[tool] %s: %s%s\n' "$name" "$status" "${reason:+ ($reason)}" >&2
}

# set_phase NAME STATUS  -> update manifest.json phases[NAME]=STATUS, bump updated time
set_phase() {
  python3 - "$1" "$2" "$OUTDIR/manifest.json" <<'PY' 2>/dev/null || true
import json, os, sys, datetime
name, status, path = sys.argv[1:4]
m = {}
if os.path.exists(path):
    try: m = json.load(open(path))
    except Exception: m = {}
m.setdefault("phases", {})[name] = status
m["updated"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
json.dump(m, open(path, "w"), indent=2)
PY
}

# done_already NAME -> 0 (true) if phase already 'done' and FORCE is unset
done_already() {
  [ "${FORCE:-0}" = "1" ] && return 1
  python3 - "$1" "$OUTDIR/manifest.json" <<'PY' 2>/dev/null
import json, os, sys
name, path = sys.argv[1:3]
try: m = json.load(open(path))
except Exception: sys.exit(1)
sys.exit(0 if m.get("phases", {}).get(name) == "done" else 1)
PY
}
