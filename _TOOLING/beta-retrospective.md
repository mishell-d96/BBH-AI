# Beta-Mode Retrospective — self-improvement ledger

Running log of each self-improvement iteration: what was slow/wrong, what changed, and how to tell it
worked. Driven by real friction from executed engagements, not speculation. Newest first.

---

## Iteration 2 — 2026-06-05 · target: demo.testfire.net (AltoroJ, training/accepted-risk-by-design)

**Context:** continuation engagement. Recon artifacts had been deleted, so re-mapped the surface first
(MAP-FIRST gate) and drove the **legacy/authenticated** surface the Iteration-1 API pass never covered.
Worked the impact-scored gaps by hand (no workflow needed — small, well-understood surface).

### What the engagement produced
- **New confirmed finding:** `POST /doLogin` (legacy form login) SQLi → **full Admin session** + read any
  account (`_EXPLOIT/2026-06-05_..._SQLi-formlogin-admin_doLogin.md`). **Closes the Iteration-1
  carry-forward lead** — admin escalation was unproven on the API `/api/login` path; the form path lands it.
  Clean 3-way differential (SQLi→main.jsp vs wrong-pw→login.jsp vs anon-admin→login.jsp).
- **New sink:** `search.jsp?query=` reflected XSS (same class as the logged `/sendFeedback` one).
- **Authz primitive:** `AltoroAccounts` base64 cookie = client-side-trusted account list (tamperable).
- **Correct NEGATIVE:** `status_check.jsp`/`serverStatusCheckService.jsp?HostName=` looked like SSRF but
  returns uniform `OK` for every host incl. unrouteable/garbage with flat timing → **inert stub, not SSRF.**
  Killed before claiming — the reachability differential did its job.

### Friction observed → improvement shipped (all generally applicable)
| # | Friction (where I was slow/wrong) | Fix shipped |
|---|-----------------------------------|-------------|
| 1 | Passed `<svg…>` inline in a curl URL; shell ate the metachars → grep showed "not reflected" → almost concluded the sink was filtered. Burned ~3 probes chasing a phantom filter. | **essential-skills → "Probe-delivery hygiene"**: never put `< > & ' " #`/space inline in a curl URL; use `curl -G --data-urlencode`. Echo-control a plain marker first; suspect the harness before the target on a negative. |
| 2 | A "status check" endpoint returned `OK` and I started reasoning about SSRF before checking it actually fetches anything. | **ssrf → "Reality check FIRST"**: reachability differential (reachable vs unreachable vs closed) before any SSRF claim; uniform-OK + flat-timing = inert stub = DISCARD. Fetch-oracle twin of the canned-200 guardrail. |
| 3 | Dumped a full multi-thousand-line transaction history to verify read access — wasteful + breaks data-minimization. | Reinforced **extract ONE marker line** (account label/balance), never the whole record — applied in the new exploit artifact; principle already in access-control-idor/reporting, now habitually enforced. |
| 4 | zsh `status` is read-only → a probe loop aborted mid-run. | One-liner in essential-skills probe-delivery hygiene (avoid reserved vars `status`/`path`/`pipestatus`). |
| 5 | Saw the `AltoroAccounts` cookie carrying the account list but had no codified "client-trusts-this-for-authz" play. | **access-control-idor → client-side-trusted authorization state**: decode every opaque cookie; if it carries object IDs/roles/balances, tamper+replay; route odd encodings to `/custom-opaque-tokens`. |

### Tooling decision (critical, deliberate)
**No new tool installed this iteration** — none was warranted. Everything needed was `curl`/`base64`/
`grep`. Resisted install-for-completeness per the install-log doctrine (signal over noise). The friction
was *technique*, not *missing binaries* — so the fixes are skill edits, not installs.

### How to tell it worked (next engagement)
- Zero false "not reflected" conclusions from shell-mangled payloads (delivery hygiene reflex).
- No SSRF claim on a validator/health endpoint without a passing reachability differential.
- Opaque authz cookies decoded + tamper-tested by default, not noticed-and-ignored.

### Carry-forward
- AltoroJ surface is now well-covered across API + legacy. Remaining untested low-value sinks
  (`subscribe.jsp`, `survey_questions.jsp`, `cgi.exe`, `default.jsp?content=` = same traversal class)
  recorded in `_RECON/demo.testfire.net/coverage.md`, skipped-with-reason (low impact / duplicate class).
- The new probe-delivery-hygiene + SSRF-reality-check rules want exercising on a *real* program to confirm
  they cut requests-to-first-proof, not just on this demo.

### Iteration 2 addendum — authenticated deep-dive (2026-06-07, operator pushed: "this isn't everything")
Drove the full **authenticated** surface (legacy bank app) that the broad pass had skimmed.
- **New confirmed:** `GET /bank/showAccount?listAccounts=N` legacy-UI **BOLA** — low-priv jsmith reads any
  account, no server-side ownership check (`_EXPLOIT/..._BOLA_legacy-showAccount.md`).
- **Big proof-discipline win — caught my own overclaim:** the doLogin-SQLi→admin chain *looked* like it
  should chain to password-change ATO via the admin `changePass` form. **It does not here** — `changePass`
  returns 200 but the side-effect check refuted it cold (old password still works, new one fails). Same for
  `addUser` (created user can't authenticate). I **corrected the doLogin exploit file** to scope impact to
  read/visibility, NOT ATO. This is the canned-200 guardrail catching a *me*-generated overclaim, not just a
  target's canned response — exactly the failure mode CLAUDE.md warns about.
- **Clean negatives recorded** (thoroughness, not exhaustion): queryxpath XPath (exceptions swallowed),
  listAccounts (int-cast, not SQLi), doTransfer (enforces source ownership), showTransactions dates
  (date-validated, not SQLi), customize.jsp content= (no traversal).

| # | Friction (where I was slow/wrong) | Fix shipped |
|---|-----------------------------------|-------------|
| 6 | A sudden uniform `302→/login` across all authenticated probes made me briefly think an endpoint had changed — it was just **session expiry**. | **access-control-idor → "Session-liveness canary"**: keep a known-good owned-resource canary; a *uniform* status flip = dead session (re-auth), only a *differential* flip is a finding. |
| 7 | **Recurring self-discipline miss:** twice dumped a multi-thousand-line transaction history to stdout to verify a read — wasteful, noisy, and violates data-minimization. The skills already say "extract one marker"; *I* didn't. | Hard rule for myself: every body-inspecting curl gets `\| grep -m1` / `head -c` **in the same command**. Treat an unbounded auth'd-page dump as a mistake, not a step. (Behavioral — reinforced here; the principle already lives in access-control-idor/reporting.) |
| 8 | `changePass`/`addUser` 200s nearly read as success. | Already covered by the canned-200 guardrail — this engagement is the **proof it works**: side-effect check (login with new vs old credential) refuted both. No new edit; logged as validation. |

**Tooling:** again **no install** — the gaps were technique/discipline, not missing binaries.

### Iteration 2 addendum 2 — SQLi data-extraction escalation (2026-06-07, operator: "continue")
Escalated the proven `/api/login` auth-bypass into **boolean-blind credential extraction** (recovered
admin's password `admin`; DB = Apache Derby, table `people`). Independently cross-checked: the API token
decodes to `base64(user):base64(pass):sig` — it **reversibly embeds the cleartext password** (secondary
finding). Both logged to `_EXPLOIT/2026-06-07_..._blindSQLi-cred-extraction_api-login.md`.

| # | Friction (where I was slow/wrong) | Fix shipped |
|---|-----------------------------------|-------------|
| 9 | Burned ~30 requests on an **`ASCII()` binary-search** before realizing **Apache Derby has no `ASCII()`** — every probe errored → read as FALSE → "extracted" all-spaces garbage. Only the calibration-against-known step caught it. | **sql-injection → blind extraction**: fingerprint the engine's string funcs FIRST (`ASCII`/`SUBSTRING` not universal; Derby uses `SUBSTR`, no `ASCII`); **calibrate the oracle against a KNOWN value** before trusting output; an all-identical result column = broken oracle, not data. |
| 10 | (validation) the **custom-opaque-tokens** decode ladder immediately revealed the token embeds creds. | No edit — skill worked as intended; logged as a validation win. |

**Discipline held:** extracted ONE 5-char password to prove the primitive, then stopped (no bulk dump).
**Tooling:** still no install — `sqlmap` would have automated this, but a hand oracle was faster to a
minimal proof and kept the request count tiny + intentional.

### Iteration 2 addendum 3 — full API surface + money-movement BOLA (2026-06-07, operator: "continue")
Enumerated the **whole** REST surface via `/swagger/properties.json` (validates Iter-1 fix #3: spec-first)
— found endpoints the earlier passes never touched (`/transfer`, `/feedback/*`, `/admin/*`). New confirmed
high-impact finding: **`POST /api/transfer` omits the source-account ownership check that the web form
enforces** → an authenticated low-priv user moves money out of any account. Proven by the unique-marker
ledger attribution (3.59 in non-owned 800000's ledger), calibrated, with no-token/garbage-token 401 controls.

| # | Friction / insight | Fix shipped |
|---|--------------------|-------------|
| 11 | The web form rejected `fromAccount=<non-owned>` ("Originating account is invalid"), which could have made me write off transfer-tampering as safe. The **API path had no such check.** | **access-control-idor → "Cross-channel authorization parity"**: a control enforced in one channel (form) is frequently absent in another (API/mobile/legacy); always replay the same tampering against every channel that performs the action, discovered via Swagger/`action=`/JS. |
| 12 | (validation) Spec-first (Iter-1 fix #3) paid off — `properties.json` gave exact field names + the full endpoint list in one request, no param guessing. | No edit — confirms the recon-mapper swagger-first rule works. |
| 13 | (validation) The state-change guardrail caught it again: `{"success":"3.59 transferred..."}` + **unchanged balances** would have read as "inert" — only the **marker in the victim's ledger** confirmed real execution (balances were corrupted overflow noise). | No edit — unique-marker attribution worked exactly as designed. |

**Tooling:** still no install. **Target status:** API + legacy surface now exhaustively mapped & tested;
remaining endpoints are inert (admin writes) or low-value (feedback). High-impact classes all proven.

### Iteration 2 addendum 4 — online-writeup cross-check found bugs I MISSED (2026-06-07, operator request)
Operator asked me to check public AltoroJ writeups for what I missed. The ZAP testapps list
(zaproxy.org/docs/testapps/altoroj) is the authoritative J2EE one. Cross-check found **3 confirmed bugs I
walked past** + 1 endpoint I never discovered:
- `GET /bank/queryxpath.jsp?query=` **reflected XSS** (attribute-context `"><script>` breakout) — I'd tested
  this page for **XPath only** and left on the negative.
- `GET /bank/customize.jsp?lang=` **reflected XSS** (raw in body) — I'd assumed `lang` was cosmetic.
- `GET /bank/customize.jsp?content=<url>` **open redirect** (`→302` to external host) — I'd tested
  `content=` for **path-traversal only** and left on the negative.
- `POST /bank/ccApply` (ZAP-listed SQLi) — endpoint **exists** (405/500), I never found it in my crawl.
  (`showTransactions` SQLi from ZAP re-checked = true negative here: strict date parsing; ZAP flags it FP too.)

**Root cause (the important lesson): tunnel vision — one vuln-class per endpoint, leave on first negative.**
I routed by the endpoint's apparent "type" (queryxpath→XPath, customize→traversal) and never tested the
reflected-XSS / open-redirect sitting in the very same params.

| # | Friction | Fix shipped |
|---|----------|-------------|
| 14 | Tested each param for the ONE class its name implied; a negative ended testing of the param, missing XSS/redirect in the same input. | **essential-skills → "One parameter → its FULL applicable class set"** + **recon-mapper → route each candidate to MULTIPLE skills**: any reflected value → also `xss`; any URL/path/file param → traversal **and** open-redirect **and** ssrf; a negative on one class does NOT close the param. |
| 15 | (process) My completeness workflow's KNOWN-list marked these pages "negative for class X", which can wrongly blacklist them for class Y in the finders. | Noted in `notes.md`: when seeding a sweep, scope negatives to *(endpoint, class)* pairs, never blacklist an endpoint outright. |

**How I could have caught it without the writeup:** the multi-class rule above would have flagged
`customize.jsp?content=` (a URL/file param → test redirect+SSRF, not just traversal) and every reflected
`query`/`lang` value (→ test XSS) during routing. Shipped so the next engagement does this by default.
**Tooling:** still no install — pure methodology gap.

### Iteration 2 addendum 5 — completeness workflow results + the meta-lesson (2026-06-07)
The 12-agent completeness sweep (`wf_eab786a7-98c`) confirmed 2 genuinely new high-impact bugs I had
missed, both **independently reproduced by the main agent** before logging:
- **API token forging** (`_EXPLOIT/..._api-token-forge_unverified-sig-plus-sqli.md`) — `ApiAuthFilter`
  doesn't verify the signature AND the token's USER_ID segment is SQL-injectable → offline-mint an admin
  token with no credential. **Highest-impact finding of the engagement.**
- **Negative `transferAmount`** inverts the ledger (`_EXPLOIT/..._negative-amount_api-transfer.md`).

**THE META-LESSON (most important of the whole engagement):** *both* new bugs were already covered by
skills I own and chose to use — `custom-opaque-tokens` **step 3** (tamper/strip the signature — flagged in
the skill as "the single highest-value 1-request test") and **step 6** (segment injection), and
`business-logic` line 36 (negative amount reverses money flow). I **decoded the token (step 2) and stopped**;
I tested `/api/transfer` for ownership but not for negative amounts. My misses this engagement were
overwhelmingly **incomplete execution of owned skills**, not missing skill content.

| # | Friction / insight | Fix shipped |
|---|--------------------|-------------|
| 16 | Stopped a skill's decision tree at the first interesting result (decoded token creds → didn't run the signature probe / segment-injection that the same skill ranks higher). | **custom-opaque-tokens**: explicit "finding an embedded credential is step 2 of 7, NOT the finish line" + new step 2b "every decoded segment is attacker-controlled input re-parsed each request → inject SQLi/XPath in the identity segment (a code path independent of /login)." + **durable memory** `run-owned-skills-to-completion`. |
| 17 | (validation) The workflow caught my incomplete execution; my manual writeup-cross-check caught what the workflow's seed blinded it to. | Process note (lesson #15): completeness needs BOTH adversarial fan-out AND an external oracle (writeups/spec); and sweep-negatives must be (endpoint,class)-scoped. |

**Behavioral root cause across this engagement** (tunnel vision #14, stop-at-decode #16, and earlier
canned-200 near-misses): I tend to stop at the first finding/negative on a surface. Countermeasures now in
skills (full-class-set routing, "tree to completion") + memory. **Tooling: still zero installs across all of
Iteration 2** — every gain was technique/discipline.

### Final tally (demo.testfire.net, all iterations) — 10 confirmed defect classes
SQLi auth-bypass (`/api/login` + `/doLogin`→admin); blind SQLi credential extraction; **API token forge
(unverified sig + SQLi in auth filter)**; BOLA ×3 (`/api/account/{n}`, `/bank/showAccount`, `/api/transfer`
source-ownership); **negative-amount** ledger inversion; reflected XSS ×4 (`/sendFeedback`, `/search.jsp`,
`/bank/queryxpath.jsp`, `/bank/customize.jsp?lang=`); **open redirect** (`customize.jsp?content=`); path
traversal→WEB-INF; credential-embedding token. Refuted/inert: admin changePass/addUser, status_check SSRF,
transfer stack-trace.

### Last thread closed — /bank/ccApply SQLi (2026-06-07)
`POST /bank/ccApply` (`passwd`, form at `/bank/apply.jsp`) confirmed SQLi → password-gate bypass: break
`'`→500 / heal `''`→200 (string-concat signature, NOT the date-validation false-positive showTransactions
had), and a wrong password + `' OR '1'='1` passes the gate that a plain wrong password fails. **Third
independent SQLi code path.** `_EXPLOIT/2026-06-07_..._SQLi-ccApply-passwd.md`. Finding it just required
following the multi-class/complete-execution discipline: locate the form (`apply.jsp` → `action=ccApply`),
learn the param (`passwd`), run the break/heal + bypass differential. **Engagement complete — no open
threads. Total: 11 confirmed defect classes, 13 _EXPLOIT artifacts. Zero tool installs across Iteration 2.**

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
