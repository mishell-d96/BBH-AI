---
name: recon-mapper
description: >-
  Full end-to-end engagement pipeline for an authorized web target: map the
  ENTIRE attack surface, verify the app's intended ("happy") flows to capture
  baselines, score the surface by business IMPACT, then route each prioritized
  candidate to the matching downstream skill. Use when the operator wants to
  hunt a whole target and asks to "map this app", "fully recon <domain>", "build
  a site map and tell me where to focus", "enumerate the attack surface", or
  "start an engagement / assessment" against a specific in-scope domain, URL, or
  IP range. This is the heavyweight orchestrator that produces shared JSON
  artifacts (attack-surface map, happy-flow baselines, impact-scored candidate
  list, skill-routing table) the vuln-class skills consume. For a quick, shallow
  surface sketch use `recon` instead. Do NOT trigger to test one specific vuln
  class (use that class's skill) or when no concrete in-scope target was given.
location: .claude/skills/recon-mapper/SKILL.md
allowed-tools: Bash(python3 *) Bash(bash *) Read Write Grep Glob
---

# recon-mapper — impact-first engagement orchestrator

The map-first entry point for hunting a whole target. It exists to flip the workflow from
"which vulns might exist?" to **"what would actually hurt this business, and what's the shortest
proven path to it?"** Every vuln-class skill is meant to run *downstream* of this, consuming its
artifacts — never cold.

`recon` = quick surface sketch. **`recon-mapper` = the full pipeline**: asset discovery → active
mapping → happy-flow baselining → **impact-scored** prioritization → skill routing, with
machine-readable artifacts the other skills read directly.

## Operating principles (non-negotiable)
1. **Authorized testing only.** A concrete in-scope target is mandatory. With no resolvable scope, **refuse and stop** — `scope_guard.py` exits non-zero; do not proceed past it.
2. **Passive before active.** Phase 1 touches only public sources. No request hits the target's own services until scope is confirmed AND the operator passes the explicit `--i-have-confirmed-scope` gate in Phase 2.
3. **Discover skills, never hardcode.** Build the downstream-skill index at runtime from the sibling skills. Route only to skills that **exist**; if a candidate has no match, flag the gap — never invent a skill.
4. **Impact over coverage.** The goal is a *ranked* list of the few highest-impact entry points and the chains they enable — not an exhaustive dump. Depth on the promising 20%.
5. **Degrade gracefully.** Missing tools are skipped and logged in `manifest.json`; the pipeline continues.
6. **Conservative & re-checked.** Low rates, no destructive actions, scope re-validated at every new host.

## Workspace layout (artifacts)
All output goes under `./_recon/<target-slug>/` (override with `OUTDIR`). `${CLAUDE_SKILL_DIR}` is this
skill's directory; helper scripts live in `${CLAUDE_SKILL_DIR}/scripts/`.
```
_recon/<target-slug>/
  manifest.json          # run state: phases done, tools run/skipped, timestamps (resumable)
  scope.json             # resolved in/out-of-scope rules + per-host verdicts
  skills_index.json      # downstream skills discovered at runtime
  phase1_assets.json     # asset inventory
  phase2_surface.json    # attack-surface / site map
  phase3_happy_flows.json# verified intended flows + baseline req/res
  phase4_candidates.json # IMPACT-SCORED vulnerability candidates (ranked)
  phase5_routing.json    # candidate -> skill hand-off + chains + gaps
  raw/                   # raw tool output + tool run/skip log
  report.md              # consolidated human-readable report
```

---

## Phase 0 — Scope & setup
**Goal:** capture target(s), confirm authorization, freeze scope, prep workspace + skill index.

1. Get the target(s) from the operator (domains, URLs, CIDRs). If none → **stop and ask**; never guess.
2. Initialise and resolve scope against the program scope files plus any explicit rules:
   ```bash
   TARGET="example.com"                       # operator-supplied, in-scope
   export OUTDIR="./_recon/${TARGET}"
   bash    ${CLAUDE_SKILL_DIR}/scripts/init_workspace.sh "$TARGET"
   python3 ${CLAUDE_SKILL_DIR}/scripts/scope_guard.py \
       --target "$TARGET" --scope-dir ../../../scope \
       --in-scope "$TARGET" --in-scope "*.${TARGET}" \
       --out "$OUTDIR/scope.json"
   ```
   `scope_guard.py` **refuses (non-zero)** if scope is empty/ambiguous or the target is out-of-scope.
3. Build the downstream-skill index (discovery, not hardcoding) and read it:
   ```bash
   python3 ${CLAUDE_SKILL_DIR}/scripts/index_skills.py --out "$OUTDIR/skills_index.json"
   ```

**Refuse and stop on:** no target; no scope; target out-of-scope; authorization unconfirmed.

---

## Phase 1 — Passive recon / asset discovery
**Goal:** enumerate assets with **zero intrusive contact**. Public sources only.
```bash
bash ${CLAUDE_SKILL_DIR}/scripts/passive_recon.sh "$TARGET" "$OUTDIR"
```
Collects (skipping+logging whatever is absent): **crt.sh** certificate transparency, **subfinder**
(passive), **DNS** (A/AAAA/CNAME/MX/TXT/NS via dig), **WHOIS**, and archived URLs
(**waybackurls**/**gau**). OSINT leads (public repos, leaked keys) are recorded as *leads* only.

After it runs: merge hostnames, dedupe, and **re-run `scope_guard.py` over every host** — anything
out-of-scope goes to `scope.json.excluded` and is never touched again.
**Output:** `phase1_assets.json`.

---

## Phase 2 — Active mapping
**Goal:** turn in-scope live hosts into a structured attack-surface map. **Active — scope-gated.**
```bash
bash ${CLAUDE_SKILL_DIR}/scripts/active_map.sh "$OUTDIR" --i-have-confirmed-scope
```
Without the gate flag the script refuses. It targets only `in_scope:true` hosts and runs, at
**conservative rates**: `httpx` (status/title/tech/TLS/WAF), `nmap` (top ports, `-sV`, polite),
`katana`/`gospider` (crawl + JS), `ffuf` (throttled content discovery), and low-noise `nuclei`
(exposure/misconfig/tech tags only — not intrusive fuzzing).

### Automated spidering is NOT complete — supplement manually (via Burp Suite Pro)
Spiders systematically miss these; walk them by hand and add to the surface map:
- **Forms-based navigation** — one URL performing many actions by body param (spider sees one endpoint, not its modes).
- **Multi-stage flows** — wizards, checkout, KYC requiring correct prior state.
- **JS-driven menus / SPA routes** not present as crawlable `<a href>`.
- **Volatile / anti-CSRF params** that change per request and break naive replay.
- **Authenticated areas** — crawl unauthenticated, then again per role with valid sessions.

**Output:** `phase2_surface.json` — `{hosts:[{host,tech,waf,ports}], endpoints:[{url,methods,params,content_type,auth,source}], js_files, secrets_leads, auth_surface}`.

---

## Phase 3 — Happy-flow verification
**Goal:** drive each significant function the **intended** way first and record the baseline
request/response. Every later abuse test is measured against this baseline.

Baseline (when present): **login, registration, profile/address update, cart/checkout, password
reset, file upload, search, and every state-changing `POST`/`PUT`/`PATCH`/`DELETE`.**

For each flow: execute it legitimately (Burp Pro to capture; `curl` for simple cases); record the
exact request and response shape; note preconditions (account/role/token/CSRF), the success signal,
and which params look attacker-influenceable. **If a flow can't be completed safely** (destructive,
real payment, irreversible, mails third parties) → do not complete it; mark `"baseline_only": true`
with the reason. Redact secrets/cookies in artifacts. **Output:** `phase3_happy_flows.json`.

---

## Phase 4 — Impact-first prioritization
**Goal:** rank the surface so the few highest-impact entry points are tested first.

**Start from the crown jewels, not the vuln list.** Identify what would actually hurt this business
and find the surfaces that touch it:
- **Authentication & session** (login, reset, MFA, SSO) → account takeover.
- **Authorization & tenancy** (object refs, roles, org boundaries) → cross-tenant data, privilege escalation.
- **Money movement** (checkout, refunds, balances, coupons) → financial loss.
- **Sensitive data stores** (PII, messages, documents, secrets) → data exposure.
- **Server-side fetch / processing / deserialization / templates** → SSRF/RCE.
- **Admin & internal** functionality → platform compromise.

Score each candidate **likelihood × impact × exposure** (1–5 each; `priority = L*I*E`, max 125),
mirroring the `CLAUDE.md` impact order (RCE/SSRF > authz/ATO > IDOR > injection > data exposure >
logic). Each candidate cites its **mapping evidence**, **suspected vuln class**, and the **baseline
flow it deviates from**. Deprioritize known-noise classes unless they chain. **Output:**
`phase4_candidates.json` (sorted by `priority`):
```json
[{"id":"C1","endpoint":"https://app.example.com/api/profile","method":"PUT",
  "evidence":"response has \"role\":\"user\" but request never sends it; JSON body merge",
  "vuln_class":"mass-assignment / prototype-pollution","signals":["json","isAdmin","role","merge"],
  "baseline_ref":"profile-update","likelihood":4,"impact":5,"exposure":3,"priority":60,
  "chain_potential":"role flip -> admin -> full account/tenant control"}]
```

---

## Phase 5 — Skill routing (with chains)
**Goal:** map each prioritized candidate to the best **existing** downstream skill and emit a precise
hand-off — and surface the **chains** that turn a medium finding into a high-impact one.
```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/route_findings.py \
    --candidates "$OUTDIR/phase4_candidates.json" \
    --skills-index "$OUTDIR/skills_index.json" \
    --happy-flows "$OUTDIR/phase3_happy_flows.json" \
    --out "$OUTDIR/phase5_routing.json"
```
`route_findings.py` scores each candidate's `vuln_class`+`signals` against the **runtime** skill index
(name+description overlap, with a class→search-term expander that still only selects skills that
exist). Per candidate it emits: `endpoint`, `baseline request/response` (from Phase 3), `hypothesis`,
`chosen skill` (slug + `/invoke`), `confidence`, `handoff_context`, and any `chain_next` (skills the
result should feed into — e.g. open-redirect → `oauth`/`ssrf`; idor → `authentication` for ATO; ssrf
→ deeper internal). Candidates below threshold are emitted `"skill": null, "gap": true` — **flag the
capability gap to the operator; do not fabricate a skill.**

Then **test highest-priority-first**, invoking each chosen skill with its `handoff_context` so it
inherits the baseline and hypothesis instead of starting cold. Pursue `chain_next` before filing
isolated low-severity bugs.

**Close the loop:** every candidate a downstream skill *proves* must be written to `../../../_EXPLOIT/`
(one file per finding, minimal `curl` repro — per `CLAUDE.md` Exploit Logging), then handed to
`/reporting`. The report's routing table should mark which candidates were confirmed and logged.

---

## Output — consolidated report
```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/build_report.py --outdir "$OUTDIR"
```
`report.md` order: **Asset inventory → Attack-surface map → Verified happy flows (baseline req/res)
→ Impact-scored candidates → Skill-routing table**, headed by scope summary + tools run/skipped. Raw
req/res stay in fenced code blocks. Always tell the operator: report path, in-scope vs excluded host
counts, top candidates, and any routing **gaps**.

## Resumability & logging
- `init_workspace.sh` creates/updates `manifest.json`; each script records tools run/skipped and phase status.
- Re-running a phase reuses existing artifacts unless `FORCE=1`. Re-running the skill resumes from the manifest.
- Every skipped tool is logged with a reason (`not installed` / `out of scope` / `disabled`). Nothing is silently dropped.
