#!/usr/bin/env python3
"""
route_findings.py — Map impact-scored candidates to EXISTING downstream skills.

For each candidate, scores its vuln_class + signals against the runtime skill
index (name + description keyword overlap). A small class->search-term expander
adds synonyms, but the final pick is ALWAYS an existing skill from the index —
nothing is hardcoded or invented. Candidates with no confident match are emitted
as gaps. Baseline req/res is pulled from the happy-flows file by baseline_ref.
Chain hints (what the result should feed into) are added when the chosen skill
is one with well-known escalation paths.

Usage:
  route_findings.py --candidates C.json --skills-index S.json
                    [--happy-flows H.json] --out routing.json [--threshold 2]
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Expanders map a concept to extra SEARCH TERMS only; selection still requires a
# real skill in the index whose name/description matches.
CLASS_SYNONYMS = {
    "idor": ["access", "control", "idor", "authorization", "bola", "privilege"],
    "access control": ["access", "control", "authorization", "privilege", "idor"],
    "mass-assignment": ["mass", "assignment", "prototype", "pollution", "api", "parameter"],
    "prototype pollution": ["prototype", "pollution", "__proto__", "merge"],
    "sqli": ["sql", "injection", "union", "blind"],
    "sql injection": ["sql", "injection"],
    "nosql": ["nosql", "mongodb", "operator"],
    "xss": ["xss", "cross-site", "scripting", "dom", "reflected", "stored"],
    "ssrf": ["ssrf", "request", "forgery", "metadata", "internal", "redirect"],
    "open redirect": ["redirect", "ssrf", "oauth", "location"],
    "rce": ["command", "injection", "deserialization", "template", "ssti", "upload"],
    "ssti": ["template", "injection", "ssti"],
    "command injection": ["command", "injection", "os"],
    "deserialization": ["deserialization", "gadget", "serialized"],
    "xxe": ["xxe", "xml", "entity"],
    "file upload": ["upload", "file", "shell"],
    "auth": ["authentication", "login", "session", "password", "mfa", "takeover"],
    "jwt": ["jwt", "token", "algorithm", "bearer"],
    "oauth": ["oauth", "openid", "sso", "redirect_uri", "social"],
    "csrf": ["csrf", "cross-site", "request", "forgery", "samesite"],
    "graphql": ["graphql", "introspection", "query"],
    "race condition": ["race", "condition", "toctou", "concurrent"],
    "cache": ["cache", "poisoning", "deception"],
    "host header": ["host", "header", "routing"],
    "request smuggling": ["smuggling", "desync", "cl.te", "te.cl"],
    "business logic": ["logic", "business", "workflow"],
    "info disclosure": ["disclosure", "information", "leak", "secret"],
    "cors": ["cors", "origin", "cross-origin"],
    "clickjacking": ["clickjacking", "frame", "ui redress"],
    "websocket": ["websocket", "cswsh", "ws"],
    "llm": ["llm", "prompt", "injection", "ai"],
    "api": ["api", "rest", "endpoint", "mass", "assignment"],
    "open redirect": ["open", "redirect", "location", "returnurl", "next", "callback", "ssrf", "oauth"],
    "subdomain takeover": ["subdomain", "takeover", "dangling", "cname", "dns", "fingerprint"],
    "secrets": ["secret", "secrets", "credential", "credentials", "key", "apikey", "token", "exposure", "leak", "git"],
    "cloud storage": ["cloud", "storage", "bucket", "s3", "gcs", "blob", "misconfig", "misconfiguration"],
    "saml": ["saml", "sso", "assertion", "signature", "xsw", "idp", "wrapping"],
    "dependency confusion": ["dependency", "confusion", "supply", "chain", "package", "npm", "pypi", "maven", "registry"],
}

# Escalation hints keyed by chosen skill slug -> skills to feed results into next.
CHAIN_NEXT = {
    "access-control-idor": ["authentication", "reporting"],  # IDOR -> ATO
    "ssrf": ["request-smuggling", "reporting"],              # SSRF -> deeper internal
    "oauth": ["jwt", "access-control-idor"],                 # token theft -> session/authz
    "jwt": ["access-control-idor"],                          # forged claims -> privilege
    "open-redirect": ["oauth", "ssrf"],
    "xss": ["csrf", "access-control-idor"],                  # XSS -> action on victim
    "file-upload": ["ssrf"],
    "prototype-pollution": ["access-control-idor"],          # privesc via polluted role
    "sql-injection": ["authentication"],                     # creds -> ATO
    "api-testing": ["access-control-idor"],                  # mass-assignment -> privilege escalation
    "subdomain-takeover": ["cors", "oauth"],                 # trusted-domain abuse -> cookie/whitelist
    "secrets-exposure": ["cloud-storage-misconfig", "access-control-idor", "jwt"],
    "cloud-storage-misconfig": ["xss", "secrets-exposure"],  # writable asset -> stored XSS / supply chain
    "saml-sso": ["access-control-idor", "xxe-injection"],    # impersonate admin / XXE in parser
    "dependency-confusion": ["reporting"],
}

WORD = re.compile(r"[a-z0-9_]+")


def tokenize(text: str):
    return set(WORD.findall((text or "").lower()))


def score(candidate: dict, skill: dict) -> int:
    vc = (candidate.get("vuln_class") or "").lower()
    terms = set()
    terms |= tokenize(vc)
    terms |= {s.lower() for s in candidate.get("signals", [])}
    for key, syns in CLASS_SYNONYMS.items():
        if key in vc or any(key in (s.lower()) for s in candidate.get("signals", [])):
            terms |= set(syns)
    hay = tokenize(skill.get("name", "")) | tokenize(skill.get("description", "")) | tokenize(skill.get("slug", ""))
    # weight slug/name matches a bit higher
    name_terms = tokenize(skill.get("name", "")) | tokenize(skill.get("slug", ""))
    base = len(terms & hay)
    bonus = len(terms & name_terms)
    # Weight name/slug matches heavily so a purpose-built skill wins over a skill that
    # merely mentions the concept in its description (e.g. secrets-exposure > information-disclosure).
    return base + 3 * bonus


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--skills-index", required=True)
    ap.add_argument("--happy-flows", default=None)
    ap.add_argument("--out", default="-")
    ap.add_argument("--threshold", type=int, default=2)
    args = ap.parse_args()

    candidates = json.loads(Path(args.candidates).read_text())
    skills = json.loads(Path(args.skills_index).read_text()).get("skills", [])
    flows = {}
    if args.happy_flows and Path(args.happy_flows).exists():
        for f in json.loads(Path(args.happy_flows).read_text()):
            flows[f.get("flow")] = f

    if not skills:
        print("[route] WARN: empty skill index — every candidate will be a gap.", file=sys.stderr)

    routed, gaps = [], 0
    for c in sorted(candidates, key=lambda x: x.get("priority", 0), reverse=True):
        ranked = sorted(((score(c, s), s) for s in skills), key=lambda t: t[0], reverse=True)
        best_score, best = (ranked[0] if ranked else (0, None))
        flow = flows.get(c.get("baseline_ref"), {})
        entry = {
            "id": c.get("id"),
            "endpoint": c.get("endpoint"),
            "method": c.get("method"),
            "priority": c.get("priority"),
            "hypothesis": c.get("evidence"),
            "vuln_class": c.get("vuln_class"),
            "baseline_request": flow.get("baseline_request"),
            "baseline_response": flow.get("baseline_response"),
            "handoff_context": {
                "influenceable_params": flow.get("influenceable_params", []),
                "success_signal": flow.get("success_signal"),
                "chain_potential": c.get("chain_potential"),
            },
        }
        if best and best_score >= args.threshold:
            entry.update({
                "skill": best["slug"],
                "invoke": best.get("invoke", f"/{best['slug']}"),
                "confidence": best_score,
                "gap": False,
                "chain_next": CHAIN_NEXT.get(best["slug"], []),
            })
        else:
            entry.update({"skill": None, "invoke": None, "confidence": best_score,
                          "gap": True,
                          "note": "no downstream skill matched — capability GAP, flag to operator"})
            gaps += 1
        routed.append(entry)

    out = {"count": len(routed), "gaps": gaps, "threshold": args.threshold, "routes": routed}
    payload = json.dumps(out, indent=2)
    if args.out == "-":
        print(payload)
    else:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
        print(f"[route] {len(routed)} candidate(s) routed, {gaps} gap(s) -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
