#!/usr/bin/env python3
"""
build_report.py — Assemble the single consolidated engagement report.

Reads the phase artifacts in --outdir and writes report.md in the required order:
Asset inventory -> Attack-surface map -> Verified happy flows (baseline req/res)
-> Impact-scored candidates -> Skill-routing table, headed by a scope + tools
summary. Idempotent: safe to re-run. Missing artifacts are noted, not fatal.

Usage:
  build_report.py --outdir _recon/<target>
"""
import argparse
import json
import os
from pathlib import Path


def load(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def fence(obj) -> str:
    if obj is None:
        return "```\n(none captured)\n```"
    if isinstance(obj, (dict, list)):
        return "```json\n" + json.dumps(obj, indent=2) + "\n```"
    return "```\n" + str(obj) + "\n```"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()
    o = Path(args.outdir)

    manifest = load(o / "manifest.json") or {}
    scope = load(o / "scope.json") or {}
    assets = load(o / "phase1_assets.json") or {}
    surface = load(o / "phase2_surface.json") or {}
    flows = load(o / "phase3_happy_flows.json") or []
    candidates = load(o / "phase4_candidates.json") or []
    routing = load(o / "phase5_routing.json") or {}

    # tools run/skipped log
    tools = []
    tlog = o / "raw" / "tools.jsonl"
    if tlog.exists():
        for line in tlog.read_text().splitlines():
            try:
                tools.append(json.loads(line))
            except Exception:
                pass

    L = []
    L.append(f"# Recon-mapper report — {manifest.get('target', '(unknown target)')}")
    L.append("")
    L.append(f"- Created: {manifest.get('created','?')}  | Updated: {manifest.get('updated','?')}")
    inscope = [v for v in scope.get("verdicts", []) if v.get("in_scope")]
    excluded = scope.get("excluded", [])
    L.append(f"- Scope: **{len(inscope)} in-scope** target(s), {len(excluded)} excluded")
    if scope.get("in_scope_rules"):
        L.append(f"  - In-scope rules: `{', '.join(scope['in_scope_rules'])}`")
    if excluded:
        L.append(f"  - Excluded: `{', '.join(excluded)}`")
    if tools:
        ran = [t['tool'] for t in tools if t['status'] == 'ok']
        skipped = [f"{t['tool']} ({t['reason']})" for t in tools if t['status'] != 'ok']
        L.append(f"- Tools run: {', '.join(ran) if ran else '(none)'}")
        if skipped:
            L.append(f"- Tools skipped: {'; '.join(skipped)}")
    L.append("")

    # 1. Asset inventory
    L.append("## 1. Asset inventory")
    hosts = assets.get("hosts", [])
    L.append(f"{len(hosts)} host(s) discovered (passive).")
    if hosts:
        L.append("")
        L.append("| Host | Sources | In scope |")
        L.append("|------|---------|----------|")
        for h in hosts[:200]:
            L.append(f"| {h.get('host')} | {', '.join(h.get('sources', []))} | {h.get('in_scope')} |")
    L.append("")

    # 2. Attack-surface map
    L.append("## 2. Attack-surface map")
    shosts = surface.get("hosts", [])
    eps = surface.get("endpoints", [])
    L.append(f"{len(shosts)} live host record(s), {len(eps)} endpoint(s), "
             f"{len(surface.get('js_files', []))} JS file(s).")
    if surface.get("auth_surface"):
        L.append("")
        L.append("**Auth surface:** " + ", ".join(f"`{u}`" for u in surface["auth_surface"][:30]))
    if surface.get("manual_supplement_required"):
        L.append("")
        L.append("**Manual supplement required (automated spidering is incomplete):**")
        for m in surface["manual_supplement_required"]:
            L.append(f"- {m}")
    L.append("")
    L.append("<details><summary>Full surface JSON</summary>\n")
    L.append(fence(surface))
    L.append("\n</details>")
    L.append("")

    # 3. Verified happy flows
    L.append("## 3. Verified happy flows (baselines)")
    if not flows:
        L.append("_No happy flows captured yet._")
    for f in flows:
        L.append("")
        tag = " _(baseline-only)_" if f.get("baseline_only") else ""
        L.append(f"### {f.get('flow','(flow)')}{tag}")
        if f.get("precondition"):
            L.append(f"- Precondition: {f['precondition']}")
        if f.get("success_signal"):
            L.append(f"- Success signal: {f['success_signal']}")
        if f.get("baseline_only") and f.get("reason"):
            L.append(f"- Not completed because: {f['reason']}")
        L.append("- Baseline request:")
        L.append(fence(f.get("baseline_request")))
        L.append("- Baseline response:")
        L.append(fence(f.get("baseline_response")))
    L.append("")

    # 4. Impact-scored candidates
    L.append("## 4. Impact-scored vulnerability candidates")
    if not candidates:
        L.append("_No candidates scored yet._")
    else:
        L.append("")
        L.append("| # | Priority | Endpoint | Suspected class | Baseline | Evidence |")
        L.append("|---|----------|----------|-----------------|----------|----------|")
        for c in sorted(candidates, key=lambda x: x.get("priority", 0), reverse=True):
            L.append(f"| {c.get('id')} | {c.get('priority')} (L{c.get('likelihood')}×I{c.get('impact')}×E{c.get('exposure')}) "
                     f"| `{c.get('method','')} {c.get('endpoint','')}` | {c.get('vuln_class')} "
                     f"| {c.get('baseline_ref','')} | {c.get('evidence','')} |")
    L.append("")

    # 5. Skill-routing table
    L.append("## 5. Skill-routing table")
    routes = routing.get("routes", [])
    if not routes:
        L.append("_No routing computed yet (run route_findings.py)._")
    else:
        L.append(f"{routing.get('count',0)} candidate(s) routed, **{routing.get('gaps',0)} gap(s)**.")
        L.append("")
        L.append("| # | Endpoint | Hypothesis | → Skill | Confidence | Chain next |")
        L.append("|---|----------|-----------|---------|-----------|-----------|")
        for r in routes:
            skill = r.get("invoke") or "**GAP — no skill**"
            chain = ", ".join(r.get("chain_next", [])) or "—"
            L.append(f"| {r.get('id')} | `{r.get('method','')} {r.get('endpoint','')}` "
                     f"| {r.get('hypothesis','')} | {skill} | {r.get('confidence')} | {chain} |")
        gaps = [r for r in routes if r.get("gap")]
        if gaps:
            L.append("")
            L.append("**Capability gaps (no matching skill — flagged for the operator):**")
            for r in gaps:
                L.append(f"- {r.get('id')} `{r.get('endpoint')}` — {r.get('vuln_class')}")
    L.append("")

    report = "\n".join(L) + "\n"
    (o / "report.md").write_text(report, encoding="utf-8")

    # mark report phase done in manifest
    mp = o / "manifest.json"
    if mp.exists():
        try:
            m = json.loads(mp.read_text())
            m.setdefault("phases", {})["report"] = "done"
            mp.write_text(json.dumps(m, indent=2))
        except Exception:
            pass
    print(f"[report] wrote {o/'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
