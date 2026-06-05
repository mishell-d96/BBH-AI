# Beta-Mode Retrospective — self-improvement ledger

Running log of each self-improvement iteration: what was slow/wrong, what changed, and how to tell it
worked. Driven by real friction from executed engagements, not speculation. Newest first.

---

## Iteration 1 — 2026-06-05/06 · target: demo.testfire.net (AltoroJ, training/accepted-risk-by-design)

**How insights were gathered:** an 8-candidate target sweep (`wf_9b675c91-675`) where every finder
reported a `friction` note, + a parallel research/skill-audit workflow (`wf_3ec21cd4-9b7`, live web),
synthesized and adversarially reviewed (`wf_277dcbb6-85d`).

### What the engagement validated (pipeline works)
Full loop ran end-to-end and produced correct verdicts: map → impact-scored candidates → routed skills →
minimal differential PoC → panel/adversarial gate. Notably the gate **caught real false-positives**:
the transfer "money-movement" finding was mechanically clean but correctly DISCARDED as
accepted-risk-by-design; C3 addUser was correctly refuted (200 ≠ side effect, inert stub).

### Friction observed → improvement shipped (all generally applicable)
| # | Friction (where I was slow/wrong) | Fix shipped |
|---|-----------------------------------|-------------|
| 1 | Nearly false-confirmed state changes on canned `200 {success}` (C3, C4) | **Canned-200 guardrail** in access-control-idor + reporting: a 200 is not a side effect — prove the action happened (login as created user / duplicate-conflict / unique ledger marker) |
| 2 | Couldn't tell missing-authn from missing-authz | **Dual control** rule: run BOTH no-token AND garbage-token (both →401, valid low-priv →200 = broken *authorization*) |
| 3 | Burned requests guessing API field/endpoint names (C3, C9) | recon-mapper Phase 2: **pull OpenAPI/Swagger spec first + scrape form `action=`/`name=`** into phase2_surface.json before vuln skills; api-testing swagger-first note |
| 4 | Hidden/mass-assignment params found by hand | **arjun** wired into recon-mapper Phase 2 + api-testing; **x8** installed for non-reflecting params |
| 5 | Path-traversal stuck on `/etc/passwd` when sink was a JSP include (C6) | path-traversal: **include-primitive triage** (empty-200 vs OS-error → context-bound dispatcher → pivot to WEB-INF), always run a known-bad-filename control; bypass ladder reordered, %00 demoted to legacy |
| 6 | Opaque token analysis ad-hoc; binary sig mangled by `echo\|cut` (TOKEN, APIGAP) | **NEW skill `custom-opaque-tokens`** — decode ladder, embedded-cred check, cheapest-first signature probes, no-secret forge, HMAC crack, binary-safe handling |
| 7 | Blind-bug confirmation referenced OAST with no way to get a host | **interactsh-client installed**; OAST standardized as default blind channel (time-delay = fallback w/ zero-delay control) across ssrf/sqli/oscmd/xxe/nosql + essential-skills |
| 8 | IDOR misreadable when object lookup empty (C7) | access-control-idor: empty/500 lookup = "untestable at tested id", **not** "refuted" |
| 9 | Attribution: generic `$1` debit not uniquely mine on a shared target | unique-marker (`3.71`) + before/after state delta; 4-curl differential skeleton in access-control-idor + reporting |
| 10 | Authz testing was a manual per-request loop | **Passive cross-account replay** (Autorize / scripted harness) as the default breadth pass; content-not-length oracle + data-marker to kill the #1 API false-positive |

### Infra/operational lessons (not skill content)
- **Subagent shells start with a broken/empty `PATH`** and `export` doesn't persist between their Bash
  calls — prepend a full PATH or use absolute binaries inside workflow agents (noted in install-log).
- **`panel.js` is main-loop-only** — subagents can't invoke the Workflow tool; the panel gate is the
  main agent's job (documented in panel.js header).

### Tools installed this iteration (see install-log.md)
arjun, dalfox, katana, interactsh-client, jwt_tool, x8.

### Skills touched: 19 edited + 1 new (`custom-opaque-tokens`). Catalog updated.

### How to tell it worked (next engagement)
- Fewer requests to first proof on API targets (swagger/arjun front-loaded).
- Zero canned-200 false-confirms (guardrail forces side-effect proof).
- Blind bugs confirmed via OAST callback instead of left as "time-based maybe".
- Opaque tokens dissected deterministically instead of ad-hoc.
- Fewer NEEDS_MORE_PROOF panel bounces on access-control (4-curl differential is panel-ready).

### Carry-forward / not done
- x8 vs arjun head-to-head not yet exercised on a live target.
- C4 changePassword ATO loop unclosable on this demo (addUser users non-authenticatable) — re-test on a
  real program.
- Schemathesis (spec-driven cross-user fuzzing) noted in api-testing as conditional; not installed (no
  standing need without an in-scope spec).
