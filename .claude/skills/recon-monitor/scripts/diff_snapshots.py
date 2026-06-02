#!/usr/bin/env python3
"""
diff_snapshots.py — diff the two most recent recon-monitor snapshots and emit ONLY
what changed, with a routing hint + scope-recheck flag per change.

The value of monitoring is the delta, not the surface. A clean diff (nothing new)
is a successful run. Each change is a LEAD that re-enters the map-first workflow
(/recon-mapper -> vuln skill -> /panel) — never a finding on its own.

Usage:
  diff_snapshots.py --outdir _RECON/<target> [--old <ts> --new <ts>]
Writes diff_<newts>.json and diff_<newts>.md under --outdir. Exit 0 always
(a clean diff is valid); exit 2 only on usage/IO error.
"""
import argparse
import json
import os
import sys
from urllib.parse import urlparse

# change-type -> (priority, where it routes in the workflow)
ROUTING = {
    "new_host":        ("HIGH",   "/recon-mapper on this host (full map + baseline); check /subdomain-takeover if it CNAMEs to an unclaimed service"),
    "newly_live_host": ("HIGH",   "/recon-mapper on this host — it just came online"),
    "new_endpoint":    ("MEDIUM", "/recon-mapper to baseline it, then the routed class (/api-testing, /access-control-idor, /sql-injection, ...)"),
    "changed_js":      ("MEDIUM", "/secrets-exposure (new keys?) + re-read for new endpoints/params/sinks -> /recon-mapper; /dom-based if new sinks"),
    "new_js":          ("MEDIUM", "/secrets-exposure + extract endpoints -> /recon-mapper"),
    "status_change":   ("LOW",    "investigate only if it exposes new function (e.g. 403->200)"),
    "new_tech":        ("LOW",    "note; pursue only if it maps to a concrete exploitable issue (not version-disclosure noise)"),
    "removed_host":    ("INFO",   "informational — asset went away"),
    "removed_endpoint":("INFO",   "informational — endpoint went away"),
}
ACTIVE_TYPES = ("new_host", "newly_live_host")  # require scope re-check before ANY active probe


def load(snap_dir):
    p = os.path.join(snap_dir, "surface.json")
    with open(p) as f:
        return json.load(f)


def list_snapshots(snaps_dir):
    if not os.path.isdir(snaps_dir):
        return []
    out = []
    for name in os.listdir(snaps_dir):
        d = os.path.join(snaps_dir, name)
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "surface.json")):
            out.append(name)
    return sorted(out)  # timestamps sort chronologically


def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def build_changes(old, new):
    changes = []
    oh, nh = old.get("hosts", {}), new.get("hosts", {})

    # hosts
    for h in sorted(set(nh) - set(oh)):
        changes.append({"type": "new_host", "key": h, "detail": f"new subdomain/host: {h}"})
    for h in sorted(set(oh) - set(nh)):
        changes.append({"type": "removed_host", "key": h, "detail": f"host gone: {h}"})
    for h in sorted(set(oh) & set(nh)):
        o, n = oh[h], nh[h]
        os_, ns = o.get("status"), n.get("status")
        if not os_ and ns:
            changes.append({"type": "newly_live_host", "key": h,
                            "detail": f"{h} now live (status {ns}, title={n.get('title')!r})"})
        elif os_ and ns and os_ != ns:
            changes.append({"type": "status_change", "key": h,
                            "detail": f"{h} status {os_} -> {ns}"})
        new_tech = sorted(set(n.get("tech", [])) - set(o.get("tech", [])))
        if new_tech:
            changes.append({"type": "new_tech", "key": h,
                            "detail": f"{h} new tech: {', '.join(new_tech)}"})

    # endpoints
    oe, ne = set(old.get("endpoints", [])), set(new.get("endpoints", []))
    for u in sorted(ne - oe):
        has_params = "?" in u and "=" in u
        looks_api = "/api" in u.lower() or "graphql" in u.lower()
        flag = " [params]" if has_params else ""
        flag += " [api]" if looks_api else ""
        changes.append({"type": "new_endpoint", "key": u, "detail": f"new endpoint: {u}{flag}",
                        "params": has_params, "api": looks_api})
    removed_eps = oe - ne
    # endpoints come and go (cache-busted URLs etc.) — summarize removals, don't spam one each
    if removed_eps:
        changes.append({"type": "removed_endpoint", "key": f"{len(removed_eps)} endpoint(s)",
                        "detail": f"{len(removed_eps)} endpoint(s) no longer seen"})

    # javascript (by content hash)
    ojs = {j["url"]: j.get("hash") for j in old.get("js", [])}
    njs = {j["url"]: j.get("hash") for j in new.get("js", [])}
    for u in sorted(set(njs) - set(ojs)):
        changes.append({"type": "new_js", "key": u, "detail": f"new JS bundle: {u}"})
    for u in sorted(set(njs) & set(ojs)):
        if ojs[u] and njs[u] and ojs[u] != njs[u]:
            changes.append({"type": "changed_js", "key": u,
                            "detail": f"JS changed (hash differs): {u}"})

    # attach priority / routing / scope flag
    for c in changes:
        prio, route = ROUTING.get(c["type"], ("LOW", "review"))
        c["priority"] = prio
        c["route"] = route
        c["scope_recheck_required"] = c["type"] in ACTIVE_TYPES
    return changes


def render_md(target, old_ts, new_ts, changes, new_surface):
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    changes = sorted(changes, key=lambda c: (order.get(c["priority"], 9), c["type"]))
    L = []
    L.append(f"# recon-monitor diff — {target}")
    L.append("")
    L.append(f"- **Previous snapshot:** `{old_ts}`")
    L.append(f"- **Current snapshot:** `{new_ts}`")
    L.append(f"- **Changes:** {len(changes)}")
    if new_surface.get("js_total_seen", 0) > new_surface.get("js_cap", 0):
        L.append(f"- ⚠️ JS coverage capped at {new_surface['js_cap']} of "
                 f"{new_surface['js_total_seen']} seen — raise `MAX_JS` for full JS diffing.")
    L.append("")
    if not changes:
        L.append("**No change since the last snapshot.** Surface is stable — nothing to action.")
        return "\n".join(L) + "\n"

    L.append("> Every entry below is a **lead**, not a finding. New surface re-enters the "
             "map-first workflow: `/recon-mapper` → routed vuln skill → minimal PoC → "
             "`/panel` → `_EXPLOIT/` + `/reporting`.")
    L.append("> **Scope-recheck-required** items must clear `scope_guard.py` before ANY active probe.")
    L.append("")
    for prio in ("HIGH", "MEDIUM", "LOW", "INFO"):
        group = [c for c in changes if c["priority"] == prio]
        if not group:
            continue
        L.append(f"## {prio} ({len(group)})")
        for c in group:
            flag = " 🔒 scope-recheck" if c.get("scope_recheck_required") else ""
            L.append(f"- **[{c['type']}]**{flag} {c['detail']}")
            L.append(f"  - → {c['route']}")
        L.append("")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--old", default=None)
    ap.add_argument("--new", default=None)
    args = ap.parse_args()

    snaps_dir = os.path.join(args.outdir, "snapshots")
    avail = list_snapshots(snaps_dir)
    if not avail:
        print("[diff] no snapshots found — run snapshot.sh first.", file=sys.stderr)
        return 2

    new_ts = args.new or avail[-1]
    if args.old:
        old_ts = args.old
    else:
        older = [t for t in avail if t < new_ts]
        if not older:
            print(f"[diff] baseline snapshot {new_ts} recorded — nothing to diff yet "
                  f"(need a second snapshot).", file=sys.stderr)
            return 0
        old_ts = older[-1]

    old = load(os.path.join(snaps_dir, old_ts))
    new = load(os.path.join(snaps_dir, new_ts))
    target = new.get("target", "target")

    changes = build_changes(old, new)
    payload = {"target": target, "old_ts": old_ts, "new_ts": new_ts,
               "change_count": len(changes), "changes": changes}

    json_path = os.path.join(args.outdir, f"diff_{new_ts}.json")
    md_path = os.path.join(args.outdir, f"diff_{new_ts}.md")
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2)
    with open(md_path, "w") as f:
        f.write(render_md(target, old_ts, new_ts, changes, new))

    high = sum(1 for c in changes if c["priority"] == "HIGH")
    print(f"[diff] {old_ts} -> {new_ts}: {len(changes)} change(s), {high} HIGH. "
          f"Report: {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
