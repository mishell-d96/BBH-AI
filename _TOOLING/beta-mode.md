# BETA MODE — active trigger + standing close-out procedure

**Presence of this file means BETA MODE is ACTIVE.** While it exists, the steps below run
**automatically as the close-out of every engagement** (and after any panel verdict), without the
operator having to ask. Delete or rename this file to pause beta mode.

This never overrides the **SCOPE GATE**, the **PANEL GATE**, or **proof discipline** — it operates
*within* them. See `CLAUDE.md` → "BETA MODE — Self-Improvement".

---

## Engagement close-out — run these in order before declaring an engagement "done"

### 1. Self-friction capture
List, honestly, where I was slow / noisy / wrong this engagement: false starts, dead ends, near-miss
overclaims, requests-to-first-proof that should have been fewer. These become the fix candidates.

### 2. Online-writeup cross-check (MANDATORY — this is the step that catches blind spots)
1. **Research.** Search for public writeups / advisories / official solution lists / walkthroughs for the
   **same target** (or, for a custom target, the **same tech/framework/CVE class**). Prefer authoritative
   sources (vendor/official solutions, OWASP, ZAP/PortSwigger, the project's own README/solutions).
2. **Diff.** Build a table: *canonical vulnerability → did I find it? → if not, why not.*
3. **Validate live, don't trust the writeup.** For each claimed miss, confirm it against the in-scope
   target with a minimal safe probe (still inside scope + rate limits + ethics). Record true-negatives too.
4. **Root-cause every miss** and answer the key question: **"How could I have found this WITHOUT the
   writeup?"** — name the methodology gap, not just the bug.

### 3. Fold the fixes back (route by generality)
- **Generally-applicable methodology** → edit the relevant **skill** (`SKILL.md`/`reference.md`) and, if it
  changes mapping/routing, the **recon flow** (`recon-mapper`). Improvements must transfer across targets —
  never target-specific hacks.
- **Target-specific gotcha** → `_RECON/<target>/notes.md`.
- **Durable behavioral lesson** → memory (one fact per file + `MEMORY.md` index line).
- **Tooling gap** → only install if a *binary* was genuinely missing (signal over noise); log every install
  to `_TOOLING/install-log.md`. If the gap was technique, the fix is a skill edit, not an install.

### 4. Log the iteration
Append an "Iteration N" entry to `_TOOLING/beta-retrospective.md`: context, what was produced, a
**friction → fix-shipped** table, "how I could have caught it without the writeup", tooling decision, and
"how to tell it worked next time". A clean cross-check (nothing missed) is logged as a **validation**, not skipped.

### 5. Coverage + hygiene check
- `_RECON/<target>/coverage.md`: every WSTG category marked tested / N-A / skipped-with-reason (no silent skips).
- Confirm every artifact I created on the target (uploads, test records, shells) was removed and verified gone.

---

## Guardrails for this loop
- The cross-check is **additive rigor**, not a license to widen scope: research is read-only/OSINT; any live
  re-validation stays within the same `./scope/` rules, rate limits, and ethics guardrails.
- On **training/accepted-risk-by-design** targets the misses are methodology lessons, not payable findings —
  the value is the *fold-back*, not a report. The panel still DISCARDs them as by-design.
- Skill edits must be **generally applicable**. If a "fix" only helps this one target, it belongs in
  `_RECON/<target>/notes.md`, not a skill.
