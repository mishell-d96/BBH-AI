#!/usr/bin/env bash
# init_workspace.sh <target> — create/refresh the engagement workspace + manifest (idempotent).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/_lib.sh"

TARGET="${1:?usage: init_workspace.sh <target>}"
: "${OUTDIR:=./_recon/${TARGET}}"
export OUTDIR
mkdir -p "$OUTDIR/raw"

python3 - "$TARGET" "$OUTDIR" <<'PY'
import json, os, sys, datetime
target, outdir = sys.argv[1:3]
path = os.path.join(outdir, "manifest.json")
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
m = {}
if os.path.exists(path):
    try: m = json.load(open(path))
    except Exception: m = {}
m.setdefault("target", target)
m.setdefault("created", now)
m["updated"] = now
m.setdefault("outdir", outdir)
phases = ["phase0_scope", "phase1_passive", "phase2_active",
          "phase3_happy", "phase4_priority", "phase5_routing", "report"]
m.setdefault("phases", {p: "pending" for p in phases})
for p in phases:
    m["phases"].setdefault(p, "pending")
json.dump(m, open(path, "w"), indent=2)
PY

set_phase phase0_scope running
echo "[init] workspace ready: $OUTDIR" >&2
echo "$OUTDIR"
