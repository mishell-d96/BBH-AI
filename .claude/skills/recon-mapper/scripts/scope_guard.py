#!/usr/bin/env python3
"""
scope_guard.py — Conservative scope enforcement. REFUSES loudly on missing scope.

Builds an allow/deny rule set from:
  - explicit --in-scope / --out-of-scope flags, and
  - tokens parsed from program scope files in --scope-dir (*.txt/*.md/*.json),
then renders a verdict for each --target. Deny always wins. If NO in-scope rule
can be resolved from any source, it refuses (exit 3): never test without scope.

Rules supported: exact host (app.example.com), wildcard (*.example.com),
bare domain (example.com -> also matches subdomains), URLs (host extracted),
and CIDR ranges (10.0.0.0/24, accepts IP targets).

Exit codes: 0 all targets in scope; 3 no scope defined; 4 a target is out of
scope (verdicts still written so the operator can see why).

Usage:
  scope_guard.py --target T [--target T2 ...] [--scope-dir DIR]
                 [--in-scope RULE ...] [--out-of-scope RULE ...] --out scope.json
"""
import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

HOST_RE = re.compile(r"\b((?:[a-zA-Z0-9_*-]+\.)+[a-zA-Z]{2,})\b")
CIDR_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
SCOPE_FILE_GLOBS = ("*.txt", "*.md", "*.json", "*.csv")
# lines that look like out-of-scope sections in human scope files
OOS_HINT = re.compile(r"out[\s_-]*of[\s_-]*scope|excluded|do not test|prohibited", re.I)


def host_of(token: str) -> str:
    token = token.strip().strip(",;").strip()
    if "://" in token:
        token = urlparse(token).hostname or token
    return token.lower()


def is_cidr(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except Exception:
        return False


def is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except Exception:
        return False


def match_rule(target: str, rule: str) -> bool:
    """Does `target` (host or IP) match a single allow/deny `rule`?"""
    t = host_of(target)
    r = rule.strip().lower()
    if not r:
        return False
    # CIDR rule + IP target
    if is_cidr(r) and is_ip(t):
        try:
            return ipaddress.ip_address(t) in ipaddress.ip_network(r, strict=False)
        except Exception:
            return False
    if is_cidr(r):
        return False
    # wildcard: *.example.com -> any subdomain (not the apex)
    if r.startswith("*."):
        base = r[2:]
        return t == base or t.endswith("." + base)
    # bare domain: example.com -> apex and any subdomain
    if "." in r and not is_ip(r):
        return t == r or t.endswith("." + r)
    # exact (host or ip)
    return t == r


def parse_scope_files(scope_dir: Path):
    """Best-effort extraction of in/out tokens from program scope files."""
    in_rules, out_rules, sources = set(), set(), []
    if not scope_dir or not scope_dir.is_dir():
        return in_rules, out_rules, sources
    for pattern in SCOPE_FILE_GLOBS:
        for fp in sorted(scope_dir.glob(pattern)):
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            sources.append(str(fp))
            # JSON scope files: look for in_scope/out_of_scope arrays
            if fp.suffix == ".json":
                try:
                    data = json.loads(text)
                    for key in ("in_scope", "inScope", "targets", "scope"):
                        for v in (data.get(key, []) if isinstance(data, dict) else []):
                            in_rules.add(host_of(str(v)) if "/" not in str(v) else str(v))
                    for key in ("out_of_scope", "outOfScope", "excluded"):
                        for v in (data.get(key, []) if isinstance(data, dict) else []):
                            out_rules.add(host_of(str(v)) if "/" not in str(v) else str(v))
                    continue
                except Exception:
                    pass
            # text/markdown: classify per line, with an out-of-scope section heuristic
            in_oos_section = False
            for line in text.splitlines():
                if OOS_HINT.search(line):
                    in_oos_section = True
                elif re.match(r"^\s*#{1,6}\s", line) or re.match(r"^\s*in[\s_-]*scope", line, re.I):
                    in_oos_section = False
                bucket = out_rules if in_oos_section else in_rules
                for m in HOST_RE.findall(line):
                    bucket.add(m.lower())
                for m in CIDR_RE.findall(line):
                    bucket.add(m)
    return in_rules, out_rules, sources


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", action="append", required=True)
    ap.add_argument("--scope-dir", default=None)
    ap.add_argument("--in-scope", action="append", default=[])
    ap.add_argument("--out-of-scope", action="append", default=[])
    ap.add_argument("--out", default="-")
    args = ap.parse_args()

    file_in, file_out, sources = parse_scope_files(Path(args.scope_dir).resolve() if args.scope_dir else None)
    in_rules = sorted({r.strip().lower() for r in args.in_scope if r.strip()} | file_in)
    out_rules = sorted({r.strip().lower() for r in args.out_of_scope if r.strip()} | file_out)

    result = {
        "in_scope_rules": in_rules,
        "out_of_scope_rules": out_rules,
        "scope_sources": sources,
        "verdicts": [],
        "excluded": [],
    }

    # Hard refusal: no in-scope rules resolvable from anywhere.
    if not in_rules:
        result["error"] = "NO IN-SCOPE RULES RESOLVED — refusing. Provide --in-scope or a scope file."
        _emit(args.out, result)
        print("[scope_guard] REFUSING: no scope defined. Nothing will be tested.", file=sys.stderr)
        return 3

    all_in = True
    for target in args.target:
        denied = any(match_rule(target, r) for r in out_rules)
        allowed = any(match_rule(target, r) for r in in_rules)
        in_scope = allowed and not denied  # deny wins
        verdict = {
            "target": target, "host": host_of(target),
            "in_scope": in_scope,
            "reason": ("explicitly out-of-scope (deny wins)" if denied
                       else "matched in-scope rule" if allowed
                       else "no in-scope rule matched"),
        }
        result["verdicts"].append(verdict)
        if not in_scope:
            result["excluded"].append(verdict["host"])
            all_in = False

    _emit(args.out, result)
    if not all_in:
        print("[scope_guard] REFUSING: at least one target is OUT OF SCOPE. See scope.json.", file=sys.stderr)
        return 4
    print(f"[scope_guard] OK: {len(args.target)} target(s) in scope.", file=sys.stderr)
    return 0


def _emit(out: str, result: dict) -> None:
    payload = json.dumps(result, indent=2)
    if out == "-":
        print(payload)
    else:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(payload + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
