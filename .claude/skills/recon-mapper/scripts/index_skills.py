#!/usr/bin/env python3
"""
index_skills.py — Discover downstream skills at runtime.

Enumerates sibling skill directories (each containing a SKILL.md), parses the
`name` and `description` from front matter, and emits a machine-readable index
so recon-mapper can route findings to skills that ACTUALLY EXIST.

Never hardcodes the catalog. Degrades gracefully if PyYAML is absent (uses a
minimal front-matter parser that understands plain, quoted, and folded/literal
block scalars: `>`, `>-`, `|`, `|-`).

Usage:
  index_skills.py [--skills-dir DIR] [--out FILE] [--exclude NAME ...]

Default --skills-dir is the parent of this script's skill directory
(i.e. .../.claude/skills), so it finds all sibling skills.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# recon-mapper and the cross-cutting helpers are not vuln-test targets for routing.
SELF_DEFAULT_EXCLUDE = {"recon-mapper"}


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _parse_frontmatter(text: str) -> dict:
    """Top-level scalar keys from YAML front matter. PyYAML if available, else a
    tolerant hand parser that handles the block scalars our skills use."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    block = text[3:end].strip("\n")

    try:
        import yaml  # type: ignore
        data = yaml.safe_load(block)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass

    out: dict = {}
    lines = block.split("\n")
    i = 0
    key_re = re.compile(r"^([A-Za-z0-9_-]+):\s?(.*)$")
    while i < len(lines):
        m = key_re.match(lines[i])
        if not m:
            i += 1
            continue
        key, val = m.group(1), m.group(2).strip()
        if val in (">", ">-", ">+", "|", "|-", "|+"):
            folded = val.startswith(">")
            i += 1
            buf = []
            while i < len(lines) and (lines[i].startswith((" ", "\t")) or lines[i].strip() == ""):
                buf.append(lines[i].strip())
                i += 1
            out[key] = (" ".join(b for b in buf if b) if folded else "\n".join(buf)).strip()
            continue
        out[key] = _strip_quotes(val)
        i += 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    default_skills_dir = Path(__file__).resolve().parents[2]  # scripts -> recon-mapper -> skills
    ap.add_argument("--skills-dir", default=str(default_skills_dir))
    ap.add_argument("--out", default="-", help="output JSON path or '-' for stdout")
    ap.add_argument("--exclude", action="append", default=[])
    args = ap.parse_args()

    skills_dir = Path(args.skills_dir).resolve()
    if not skills_dir.is_dir():
        print(f"[index_skills] skills dir not found: {skills_dir}", file=sys.stderr)
        return 2

    exclude = SELF_DEFAULT_EXCLUDE | set(args.exclude)
    skills = []
    for sub in sorted(skills_dir.iterdir()):
        if not sub.is_dir():
            continue
        sk = sub / "SKILL.md"
        if not sk.is_file() or sub.name in exclude:
            continue
        try:
            fm = _parse_frontmatter(sk.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            print(f"[index_skills] WARN: parse failed {sk}: {e}", file=sys.stderr)
            fm = {}
        skills.append({
            "slug": sub.name,
            "name": fm.get("name") or sub.name,
            "description": " ".join(str(fm.get("description") or "").split()),
            "invoke": f"/{sub.name}",
            "path": str(sk),
            "has_reference": (sub / "reference.md").is_file(),
            "has_cheatsheet": (sub / "cheatsheet.md").is_file(),
        })

    payload = json.dumps({"skills_dir": str(skills_dir), "count": len(skills), "skills": skills}, indent=2)
    if args.out == "-":
        print(payload)
    else:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
        print(f"[index_skills] indexed {len(skills)} skill(s) -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
