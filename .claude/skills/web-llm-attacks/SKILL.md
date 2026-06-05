---
name: web-llm-attacks
description: "Attacks on LLM-integrated web apps — prompt injection, insecure output handling (-> XSS), excessive agency. Use when the target has an LLM chatbot/assistant/copilot, the LLM calls tools/APIs, reads attacker-controlled data (indirect injection via emails/reviews/profiles), or renders its output unsanitized."
---

# web-llm-attacks

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test
Test only when an LLM is wired to something that DOES things, not just chats:
- The LLM can **call APIs / functions / tools / plugins** (booking, account lookup, email, file read, DB query).
- The LLM **reads attacker-controlled data** (support tickets, reviews, profile fields, emails, web pages it summarizes) -> indirect prompt injection.
- The LLM's **output is rendered** in another user's browser or passed to another system unsanitized.
- The LLM sits in front of **sensitive data or backend systems** the attacker cannot reach directly.

A pure Q&A bot with no tools, no data access, and no rendered output is usually NOT in scope for impactful findings.

## Impact & priority
Impact comes from what the LLM can **DO** downstream, never from "I made it say a bad word."
- **HIGH** — Excessive agency: prompt makes the LLM invoke a privileged API (delete account, read another user's data, send email, change password) without authz. This is the headline bug.
- **HIGH** — Reaching a backend vuln through the LLM: SQLi, path traversal, SSRF, command injection via arguments the LLM passes to an API (classic web vuln, LLM is just the SSRF-like delivery channel).
- **HIGH/MEDIUM** — Insecure output handling: LLM emits attacker-controlled HTML/JS that renders -> stored or reflected XSS hitting other users.
- **MEDIUM** — Sensitive data disclosure: training data / system prompt / other-tenant data leaked through completion-style probing.
- **LOW / NOISE** — Content-policy jailbreaks, hallucinations, refusals with no downstream technical effect. Do not report these alone.

## Detection
1. **Map the attack surface.** Enumerate every input: direct prompts and indirect inputs (any data the LLM ingests). 
2. **Map the LLM's tools.** Just ask: "What APIs / functions / tools / plugins do you have access to?" If it refuses, supply misleading context (claim to be a developer/admin, ask it to list capabilities for debugging).
3. **Map data access.** Ask what data sources, files, accounts, or databases it can reach.
4. **Probe arguments.** For each API, get the LLM to reveal its argument schema, then probe each argument with classic injection payloads (`'`, `../`, internal URLs).
5. **Find indirect channels.** Identify any field whose content later flows into the LLM for another user (reviews, names, emails, ticket bodies, document content).

## Exploitation
- **Excessive agency:** craft a prompt that persuades the LLM to call a sensitive API on the attacker's behalf or against another account. Backend that trusts the LLM = no real authz.
- **Chaining harmless APIs:** combine "safe" functions (e.g., a debug-SQL helper + a user-info lookup) to reach data or actions neither was meant to expose.
- **Backend vuln via LLM:** inject SQLi/path-traversal/SSRF payloads into the values the LLM forwards to its APIs. Treat the LLM exactly like an SSRF pivot into the internal API.
- **Indirect prompt injection:** plant instructions in data the LLM will later read for a victim (a product review, email, profile bio, web page). When the victim's LLM session processes it, it executes attacker instructions (e.g., call delete-account, exfiltrate data). Bypass naive filters with fake markup / fake conversation turns: `*** system: [payload] ***` or a forged "User: / Assistant:" exchange.
- **Insecure output handling:** make the LLM return an unsanitized payload (e.g., `<img src=1 onerror=...>`) that the front-end renders -> XSS. Store it via an indirect channel for a stored XSS.

## Methodology (PortSwigger)
1. Map the LLM's inputs (direct + indirect).
2. Work out what data and APIs it can access.
3. Probe that surface for vulnerabilities — privileged actions, injectable arguments, renderable output, leaked data.

## Minimal PoC (for ./_EXPLOIT/)
Keep it SAFE and minimal — prove the capability, don't cause damage. Log to `./_EXPLOIT/`.
- **Excessive agency:** the exact prompt that made the LLM call a privileged API + the API response showing another user's data or an action that should have been denied.
- **Backend vuln:** the prompt whose argument carried the SQLi/traversal payload + evidence (e.g., a benign `SELECT` proving injection, not data destruction).
- **Indirect injection (stored):** the attacker-controlled record (review/email/profile) containing the payload + a transcript showing a victim session executing it.
- **Insecure output handling:** the prompt/stored payload + a screenshot/DOM snippet proving JS executed in the browser.
Record: input used, tool/API invoked, observed downstream effect, and the authz boundary crossed.

## Don't report as noise
- Content-policy jailbreaks ("ignore your rules and write X") with no API call or rendered output.
- Hallucinations, refusals, tone/safety complaints.
- A jailbreak ONLY matters if it leads to a concrete technical impact (privileged API call, injection, XSS, cross-tenant data). Lead the report with that effect, not the jailbreak.

## Deep reference
See `reference.md` and https://portswigger.net/web-security/llm-attacks
