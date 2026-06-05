---
name: recon-monitor
description: "Continuous surface monitoring of an already-mapped target — snapshot on a cadence and diff vs the last snapshot, surfacing only what CHANGED (new subdomains, newly-live hosts, new endpoints/params, changed JS, new tech), routed back into recon-mapper. Use to 'monitor <target>', 'watch for new subdomains/endpoints', 'scheduled re-recon'. Needs a recon-mapper baseline first."
location: .claude/skills/recon-monitor/SKILL.md
allowed-tools: Bash(python3 *) Bash(bash *) Read Write Grep Glob
---

# recon-monitor — continuous surface diffing

The 2026 edge in mature programs is rarely a cleverer payload — it is **seeing the asset, endpoint,
or JS bundle nobody else has tested yet**. Programs ship changes constantly; the surface that
`/recon-mapper` froze last week is already stale. This skill turns recon from a one-shot map into a
**watch**: snapshot the surface, diff against the previous snapshot, and surface **only the delta**
— then feed the delta straight back into the map-first workflow.

`recon-mapper` = "map the whole target once, score it, route it." **`recon-monitor` = "re-snapshot on
a cadence and tell me only what changed since last time."** It runs *after* a baseline exists and
*feeds* `recon-mapper` whenever the surface drifts.

## Operating principles (non-negotiable)
1. **Baseline first.** A target must already have been mapped by `/recon-mapper` (or at least one prior snapshot must exist). With no baseline, run `/recon-mapper` — don't start here.
2. **SCOPE GATE on every host, every run.** New subdomains appear *between* runs and may be **out of scope**. Every discovered host is re-checked through `recon-mapper`'s `scope_guard.py` (the single source of scope truth — never reimplemented here) **before any active probe touches it.** Out-of-scope hosts are recorded passively and never fingerprinted, crawled, or fetched.
3. **Passive discovery is always safe; live fingerprinting is ACTIVE and gated.** Subdomain/CT discovery touches only public sources. `httpx`/crawl/JS-fetch run only against `in_scope:true` hosts **and** only when the operator passes `--i-have-confirmed-scope`.
4. **Diff = signal. Report only the delta.** A run that surfaces nothing new is a *successful* run, not a failure. Never re-dump the whole surface; emit only added/changed/removed.
5. **Respect rate limits — repeatedly.** A *scheduled* loop hits a live target again and again. Stay well under the program's stated rate caps every single run; slower is fine. If a cadence would breach limits, lengthen the interval.
6. **Degrade gracefully.** A missing tool is logged and skipped, never fatal. The diff still runs on whatever was captured.

## Workspace layout (artifacts)
Reuses the target's existing `./_RECON/<target-slug>/` tree. `${CLAUDE_SKILL_DIR}` is this skill's
directory; `scope_guard.py` is borrowed from the sibling `recon-mapper` skill.
```
_RECON/<target-slug>/
  snapshots/
    LATEST                       # timestamp of the most recent snapshot
    <ts>/                        # one dir per snapshot run (UTC timestamp)
      surface.json               # captured surface: hosts{live state}, endpoints[], js[{url,hash}]
      scope.json                 # per-host scope verdicts for THIS run's discovered hosts
      inscope.txt                # in-scope hosts that were allowed to be probed
      raw/                       # raw tool output (crt.sh, subfinder, httpx, urls, js hashes)
  diff_<newts>.json              # machine-readable delta + routing hints (new vs previous)
  diff_<newts>.md                # operator-facing change report
```

---

## How to run

### 1. Snapshot (capture current surface)
```bash
TARGET="example.com"                          # operator-supplied, already baselined & in-scope
export OUTDIR="./_RECON/${TARGET}"

# Passive only (safe anywhere) — discovery + scope verdicts, no live touch:
bash ${CLAUDE_SKILL_DIR}/scripts/snapshot.sh "$TARGET" "$OUTDIR"

# Full snapshot (ACTIVE live fingerprint of in-scope hosts) — requires the gate flag:
bash ${CLAUDE_SKILL_DIR}/scripts/snapshot.sh "$TARGET" "$OUTDIR" --i-have-confirmed-scope
```
`snapshot.sh`: pulls passive subdomains (crt.sh + subfinder), **re-runs `scope_guard.py` over every
discovered host**, and — only with the gate, only on in-scope hosts — fingerprints with `httpx`
(status/title/tech/server + body hash), harvests URLs (`gau`/`waybackurls` + `katana`), and fetches +
SHA-256-hashes JavaScript bundles (capped by `MAX_JS`, default 50 — overage is logged, never silently
dropped). Writes `snapshots/<ts>/surface.json`.

### 2. Diff against the previous snapshot
```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/diff_snapshots.py --outdir "$OUTDIR"
```
Compares the two most recent snapshots and emits **only the delta**: new / removed / newly-live hosts,
status & tech changes, new endpoints (params flagged), and changed/new JS (by content hash). Each
change carries a **routing hint** and a **scope-recheck flag**. First-ever run records a baseline and
reports "nothing to diff yet."

---

## Scheduling (the whole point)
Run it unattended with the workspace's own `/loop` or `/schedule` skill. Pick a cadence the program's
rate limits and change-frequency justify — **daily or weekly is plenty** for most targets; never tighter
than the rate caps allow. Examples:
- One-off / interactive: just run the two commands above.
- Recurring locally: `/loop` the snapshot+diff pair on a daily interval.
- Remote cron: `/schedule` a daily run that snapshots, diffs, and surfaces any non-empty `diff_<ts>.md`.

A run with an empty diff should stay quiet. A run with a non-empty diff should hand the delta to the
workflow below.

## Diff → route (close the loop)
Treat every diff entry as a fresh candidate entering the map-first workflow — **never test it cold,
never report it un-paneled.**
- **🚨 New or changed AUTH surface (TOP PRIORITY)** — a new `/login` `/oauth` `/saml` `/reset` `/mfa` endpoint, a changed token / `Set-Cookie` shape, or a new IdP → **escalate immediately** to `/recon-mapper` for an auth baseline, then route to `/authentication`, `/oauth`, `/jwt`, `/saml-sso` (and `/custom-opaque-tokens` for a non-JWT token shape). **Auth-surface drift OUTRANKS generic new endpoints** — a re-architected login/SSO/session flow is where pre-disclosure ATO chains live; chase it before anything else in the diff.
- **New / newly-live host** → re-run `/recon-mapper` scoped to that host (full map + happy-flow baseline + impact scoring). Also check `/subdomain-takeover` if it resolves to a dangling/unclaimed service.
- **Changed or new JS bundle** → `/secrets-exposure` (new keys/tokens) and re-read for **new endpoints/params/sinks** → feed those to `/recon-mapper`; `/dom-based` if new client-side sinks appear.
- **New endpoint (esp. with params or `/api`)** → `/recon-mapper` to baseline it, then the routed class (`/api-testing`, `/access-control-idor`, `/sql-injection`, …).
- **New tech / version** → note it; pursue only if it maps to a concrete, exploitable issue (not version-disclosure noise).
- **Removed host/endpoint** → informational; usually not actionable.

Then the standard doctrine applies: impact hypothesis → highest-impact-first testing → **minimal safe
PoC → `/panel` gate → `_EXPLOIT/` + `/reporting`**. The diff only tells you *where to look first*; it
is never itself a finding.

## Don't (anti-noise)
- Don't report "the attack surface changed" as a finding — it's a lead, not a vuln.
- Don't probe a newly-discovered host before `scope_guard.py` clears it. New subdomain ≠ in scope.
- Don't tighten the schedule to beat other hunters at the cost of breaching rate limits.
- Don't re-emit the full surface each run; the value is strictly the delta.
- Don't skip `/recon-mapper` on new surface and jump straight to a vuln skill — new assets test cold otherwise.
