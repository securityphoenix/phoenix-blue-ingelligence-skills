#!/usr/bin/env python3
"""Local reachability evidence for a vulnerable dependency.

Phoenix says a library version is vulnerable. It does NOT publish the vulnerable
function name. This script measures, in the user's own repository:

  L1  direct or transitive dependency
  L2  is the package imported in first-party code
  L3  which of its symbols the code calls
  L4  does the CVE description name a symbol we call

IT NEVER CLEARS A FINDING. Static search cannot see dynamic imports, reflection,
re-exports, plugin loaders, build-time generation, or a dependency calling the
vulnerable code on your behalf. A low result lowers priority. Nothing more.

Usage:
  reachability.py --root . --purl pkg:npm/lodash@4.17.20 \\
      --cve-desc "…vulnerable to Command Injection via the template function."

  # several CVE descriptions at once
  reachability.py --root . --purl pkg:npm/lodash@4.17.20 \\
      --cve CVE-2021-23337 "…via the template function." \\
      --cve CVE-2020-28500 "…via the toNumber, trim and trimEnd functions."

Output is JSON on stdout. Exit code is always 0 unless the arguments are wrong;
"no evidence found" is a result, not a failure.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Set

# --------------------------------------------------------------------------
# ecosystem table
# --------------------------------------------------------------------------

#: Per ecosystem: source extensions, directories that are NOT first-party, the
#: manifest that defines "direct", and the lockfile that defines "present".
ECOSYSTEMS = {
    "npm": {
        "exts": [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"],
        "exclude": ["node_modules", "dist", "build", "out", ".next", "coverage", "vendor"],
        "manifest": ["package.json"],
        "lock": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    },
    "pypi": {
        "exts": [".py", ".pyi"],
        "exclude": [".venv", "venv", "site-packages", "build", "dist", ".tox", ".eggs"],
        "manifest": ["pyproject.toml", "requirements.in", "requirements.txt", "setup.py"],
        "lock": ["poetry.lock", "Pipfile.lock", "requirements.txt"],
    },
    "golang": {
        "exts": [".go"],
        "exclude": ["vendor"],
        "manifest": ["go.mod"],
        "lock": ["go.sum"],
    },
    "gem": {
        "exts": [".rb", ".rake"],
        "exclude": ["vendor", ".bundle"],
        "manifest": ["Gemfile"],
        "lock": ["Gemfile.lock"],
    },
    "cargo": {
        "exts": [".rs"],
        "exclude": ["target"],
        "manifest": ["Cargo.toml"],
        "lock": ["Cargo.lock"],
    },
    "maven": {
        "exts": [".java", ".kt", ".scala", ".groovy"],
        "exclude": ["target", "build", ".gradle"],
        "manifest": ["pom.xml", "build.gradle", "build.gradle.kts"],
        "lock": [],
    },
    "composer": {
        "exts": [".php"],
        "exclude": ["vendor"],
        "manifest": ["composer.json"],
        "lock": ["composer.lock"],
    },
    "nuget": {
        "exts": [".cs", ".fs", ".vb"],
        "exclude": ["bin", "obj", "packages"],
        "manifest": [],
        "lock": ["packages.lock.json"],
    },
}

#: Distribution name -> import name. These differ often enough that an absent
#: import is usually a naming miss, not a real absence.
IMPORT_ALIASES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL",
    "python-dateutil": "dateutil", "msgpack-python": "msgpack",
    "scikit-learn": "sklearn", "opencv-python": "cv2",
    "python-jose": "jose", "pycryptodome": "Crypto",
    "protobuf": "google.protobuf", "typing-extensions": "typing_extensions",
    "attrs": "attr", "setuptools": "setuptools",
}


# --------------------------------------------------------------------------
# purl
# --------------------------------------------------------------------------

def parse_purl(purl: str) -> Dict[str, str]:
    s = purl[4:] if purl.startswith("pkg:") else purl
    version = ""
    if "@" in s:
        head, _, version = s.rpartition("@")
        # an npm scope also starts with @; only treat the LAST @ as a version
        # separator when something precedes it.
        if head:
            s = head
        else:
            version = ""
    eco, _, name = s.partition("/")
    return {"ecosystem": eco.lower(), "name": name, "version": version}


def import_name(ecosystem: str, name: str) -> str:
    """The token that appears in source, which is not always the package name."""
    if ecosystem == "pypi":
        key = name.lower().replace("_", "-")
        return IMPORT_ALIASES.get(key, name.replace("-", "_"))
    if ecosystem == "maven":
        return name.split("/")[-1]
    return name


# --------------------------------------------------------------------------
# L1 — direct or transitive
# --------------------------------------------------------------------------

def level1_direct(root: str, eco: str, name: str) -> Dict[str, object]:
    spec = ECOSYSTEMS.get(eco, {})
    checked: List[str] = []
    for fn in spec.get("manifest", []):
        p = os.path.join(root, fn)
        if not os.path.isfile(p):
            continue
        checked.append(fn)
        try:
            text = open(p, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if fn == "package.json":
            try:
                d = json.loads(text)
            except ValueError:
                continue
            declared = set(d.get("dependencies") or {}) | set(d.get("devDependencies") or {})
            if name in declared:
                dev = name in (d.get("devDependencies") or {})
                return {"relationship": "direct", "dev_only": dev,
                        "evidence": f"{fn} declares it", "manifests_checked": checked}
        else:
            # A bare name match in a manifest is weaker than parsed JSON, so it
            # is reported as such rather than asserted.
            #
            # PyPI distribution names are case-insensitive and treat "-", "_"
            # and "." as equivalent (PEP 503). `pyyaml==5.3.1` in a
            # requirements file IS the distribution `PyYAML`, so an exact,
            # case-sensitive match would wrongly call a direct dependency
            # transitive. npm, Maven and crates names stay case-sensitive.
            if eco == "pypi":
                norm = re.sub(r"[-_.]+", "[-_.]", re.escape(name))
                pat = rf"(?mi)^[^#\n]*(?<![\w.-]){norm}(?![\w-])"
            else:
                pat = rf"(?m)^[^#\n]*\b{re.escape(name)}\b"
            if re.search(pat, text):
                return {"relationship": "direct", "dev_only": None,
                        "evidence": f"{fn} mentions it (text match, not parsed)",
                        "manifests_checked": checked}

    if not checked:
        return {"relationship": "unknown", "dev_only": None,
                "evidence": "no manifest found for this ecosystem",
                "manifests_checked": []}
    return {"relationship": "transitive", "dev_only": None,
            "evidence": f"absent from {', '.join(checked)}",
            "manifests_checked": checked}


# --------------------------------------------------------------------------
# source walk
# --------------------------------------------------------------------------

def iter_sources(root: str, eco: str) -> List[str]:
    spec = ECOSYSTEMS.get(eco)
    if not spec:
        return []
    exts = tuple(spec["exts"])
    skip = set(spec["exclude"]) | {".git", ".hg", ".svn", "__pycache__"}
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith(exts) and ".min." not in fn:
                out.append(os.path.join(dirpath, fn))
    return out


# --------------------------------------------------------------------------
# L2 — is it imported
# --------------------------------------------------------------------------

def import_patterns(eco: str, imp: str) -> List[str]:
    e = re.escape(imp)
    if eco == "npm":
        return [rf"require\(\s*['\"]{e}(/[^'\"]*)?['\"]\s*\)",
                rf"from\s+['\"]{e}(/[^'\"]*)?['\"]",
                rf"import\(\s*['\"]{e}(/[^'\"]*)?['\"]\s*\)"]
    if eco == "pypi":
        return [rf"^\s*import\s+{e}\b", rf"^\s*from\s+{e}[\s.]",
                rf"importlib\.import_module\(\s*['\"]{e}"]
    if eco == "golang":
        return [rf"['\"][^'\"]*{e}[^'\"]*['\"]"]
    if eco == "gem":
        return [rf"require\s+['\"]{e}", rf"require_relative\s+['\"]{e}"]
    if eco == "cargo":
        return [rf"\buse\s+{e}::", rf"\bextern\s+crate\s+{e}\b"]
    if eco == "maven":
        return [rf"^\s*import\s+[\w.]*{e}[\w.]*"]
    if eco == "composer":
        return [rf"\buse\s+[\w\\]*{e}", rf"require[\w_]*\(\s*['\"][^'\"]*{e}"]
    if eco == "nuget":
        return [rf"^\s*using\s+[\w.]*{e}"]
    return [re.escape(imp)]


def level2_imports(files: List[str], eco: str, imp: str, root: str) -> Dict[str, object]:
    pats = [re.compile(p, re.M) for p in import_patterns(eco, imp)]
    sites: List[Dict[str, object]] = []
    aliases: Set[str] = set()
    deep: Set[str] = set()

    for path in files:
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if imp not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if not any(p.search(line) for p in pats):
                continue
            sites.append({"file": os.path.relpath(path, root),
                          "line": lineno, "code": line.strip()[:160]})
            aliases |= _aliases_from(line, eco, imp)
            m = re.search(rf"['\"]{re.escape(imp)}/([\w\-./]+)['\"]", line)
            if m:
                deep.add(m.group(1).split("/")[-1])

    return {"imported": bool(sites), "import_count": len(sites),
            "files": sorted({str(s["file"]) for s in sites}),
            "sites": sites[:40], "aliases": sorted(aliases),
            "deep_import_symbols": sorted(deep)}


def _aliases_from(line: str, eco: str, imp: str) -> Set[str]:
    """Local names bound to the package on this import line."""
    out: Set[str] = set()
    if eco == "npm":
        for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*require", line):
            out.add(m.group(1))
        for m in re.finditer(r"import\s+(\w+)\s*(?:,|from)", line):
            out.add(m.group(1))
        for m in re.finditer(r"import\s+\*\s+as\s+(\w+)", line):
            out.add(m.group(1))
        for m in re.finditer(r"(?:const|import)\s*\{([^}]*)\}", line):
            for part in m.group(1).split(","):
                part = part.strip()
                if not part:
                    continue
                out.add(part.split(" as ")[-1].strip())
    elif eco == "pypi":
        m = re.match(r"\s*import\s+[\w.]+\s+as\s+(\w+)", line)
        if m:
            out.add(m.group(1))
        elif re.match(r"\s*import\s", line):
            out.add(imp.split(".")[0])
        for m in re.finditer(r"from\s+[\w.]+\s+import\s+(.+)", line):
            for part in m.group(1).split(","):
                part = part.strip().strip("()")
                if part and part != "*":
                    out.add(part.split(" as ")[-1].strip())
    return {a for a in out if a and a.isidentifier()}


# --------------------------------------------------------------------------
# L3 — which symbols are called
# --------------------------------------------------------------------------

def level3_symbols(files: List[str], aliases: List[str], root: str) -> Dict[str, object]:
    used: Dict[str, int] = {}
    where: Dict[str, Set[str]] = {}
    if not aliases:
        return {"symbols": [], "note": "no import alias resolved, cannot enumerate calls"}

    member = re.compile(
        r"(?:^|[^A-Za-z0-9_.])(" + "|".join(re.escape(a) for a in aliases) +
        r")\s*\.\s*([A-Za-z_]\w*)")
    bare = re.compile(
        r"(?:^|[^A-Za-z0-9_.])(" + "|".join(re.escape(a) for a in aliases) + r")\s*\(")

    for path in files:
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        rel = os.path.relpath(path, root)
        for m in member.finditer(text):
            sym = m.group(2)
            used[sym] = used.get(sym, 0) + 1
            where.setdefault(sym, set()).add(rel)
        for m in bare.finditer(text):
            # a named import called directly, e.g. template(...)
            sym = m.group(1)
            used[sym] = used.get(sym, 0) + 1
            where.setdefault(sym, set()).add(rel)

    return {"symbols": sorted(used),
            "counts": dict(sorted(used.items(), key=lambda kv: -kv[1])),
            "files_by_symbol": {k: sorted(v) for k, v in where.items()}}


# --------------------------------------------------------------------------
# L4 — CVE symbol extraction
# --------------------------------------------------------------------------

_NOISE = {"the", "and", "or", "a", "an", "of", "in", "via", "this", "that",
          "function", "functions", "method", "methods", "api", "apis",
          "call", "calls", "is", "are", "to", "it", "when", "with"}

_PATTERNS = [
    # "via the template function" / "via the toNumber, trim and trimEnd functions"
    r"\b(?:via|in|within|through|using|from)\s+the\s+"
    r"([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*(?:\s*,?\s*and\s+[A-Za-z_][\w.]*)?)"
    r"\s+(?:functions?|methods?|APIs?|calls?)\b",
    r"`([A-Za-z_][\w.]*)\s*\(\s*\)`",       # `parse_url()`
    r"`([A-Za-z_][\w.]{2,})`",              # `template`
    r"\b([a-z_][\w]*(?:\.[\w]+)+)\b",       # urllib3.util.parse_url
]


def cve_symbols(desc: str) -> List[str]:
    """Candidate vulnerable symbol names named in a CVE description.

    A camelCase regex alone is not enough: it finds `toNumber` and `trimEnd`
    but misses `template` and `trim`, which are plain lowercase words.
    """
    out: List[str] = []
    for pat in _PATTERNS:
        for m in re.finditer(pat, desc or ""):
            for tok in re.split(r"\s*(?:,|\band\b)\s*", m.group(1)):
                tok = tok.strip().rstrip("()").strip(".")
                if tok and tok.lower() not in _NOISE and len(tok) > 2:
                    out.append(tok)
    seen: Set[str] = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def level4_match(named: List[str], used: List[str], deep: List[str]) -> Dict[str, object]:
    used_set = {u.lower() for u in used} | {d.lower() for d in deep}
    hits = [n for n in named if n.lower() in used_set
            or n.split(".")[-1].lower() in used_set]
    if not named:
        return {"cve_named_symbols": [], "matched": [],
                "signal": "no_symbol_in_description",
                "meaning": "The CVE text names no function. Reachability could "
                           "not be narrowed past import presence."}
    if hits:
        return {"cve_named_symbols": named, "matched": hits,
                "signal": "symbol_match",
                "meaning": f"The CVE names {hits} and this code calls it. "
                           f"Treat as likely reachable."}
    return {"cve_named_symbols": named, "matched": [],
            "signal": "no_symbol_match",
            "meaning": f"No call to {named} was found among {len(used)} used "
                       f"members. LOWER PRIORITY. This is not a clearance."}


# --------------------------------------------------------------------------
# priority
# --------------------------------------------------------------------------

def priority(l1: Dict, l2: Dict, l4: Optional[Dict], *,
             actively_exploited: bool, ransomware: bool, severity: str) -> Dict[str, str]:
    if actively_exploited:
        return {"priority": "P1", "because": "actively exploited — local reachability does not lower this"}
    if ransomware:
        return {"priority": "P1", "because": "linked to ransomware — local reachability does not lower this"}

    high = (severity or "").upper() in {"CRITICAL", "HIGH"}
    direct = l1.get("relationship") == "direct"
    unknown = l1.get("relationship") == "unknown"
    imported = bool(l2.get("imported"))
    matched = bool(l4 and l4.get("matched"))

    if unknown or (imported and l4 and l4.get("signal") == "no_symbol_in_description"):
        return {"priority": "P2", "because": "could not determine — an unknown is not a negative"}
    if high and direct and matched:
        return {"priority": "P1", "because": "high severity, direct dependency, vulnerable symbol called"}
    if high and direct and imported:
        return {"priority": "P2", "because": "high severity, direct dependency, imported"}
    if high and imported:
        return {"priority": "P2", "because": "high severity, reached through a parent dependency"}
    if high:
        return {"priority": "P3", "because": "high severity, no first-party import found"}
    if imported:
        return {"priority": "P3", "because": "imported"}
    return {"priority": "P4", "because": "no first-party import found — batch it"}


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

DISCLAIMER = (
    "Reachability was measured by searching this repository, not by Phoenix. "
    "Static search cannot see dynamic imports, reflection, re-exports, plugin "
    "loaders, build-time generation, or a dependency calling the vulnerable "
    "code on your behalf. Many CVEs (prototype pollution, parser bugs, unsafe "
    "defaults) have no call site to find at all. A low result LOWERS PRIORITY "
    "and NEVER clears a finding."
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="repository root to search")
    ap.add_argument("--purl", required=True, help="pkg:npm/lodash@4.17.20")
    ap.add_argument("--cve", nargs=2, action="append", metavar=("CVE_ID", "DESCRIPTION"),
                    default=[], help="repeatable: a CVE id and its description")
    ap.add_argument("--cve-desc", default=None,
                    help="a single CVE description, when you have no id")
    ap.add_argument("--severity", default="", help="CRITICAL|HIGH|MEDIUM|LOW")
    ap.add_argument("--actively-exploited", action="store_true")
    ap.add_argument("--ransomware", action="store_true")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(json.dumps({"error": f"not a directory: {root}"}), file=sys.stderr)
        return 2

    p = parse_purl(args.purl)
    eco, name = p["ecosystem"], p["name"]
    if eco not in ECOSYSTEMS:
        print(json.dumps({
            "purl": args.purl, "error": f"unsupported ecosystem {eco!r}",
            "supported": sorted(ECOSYSTEMS), "disclaimer": DISCLAIMER}, indent=2))
        return 0

    imp = import_name(eco, name)
    files = iter_sources(root, eco)

    l1 = level1_direct(root, eco, name)
    l2 = level2_imports(files, eco, imp, root)
    aliases = list(l2["aliases"]) or ([imp] if l2["imported"] else [])
    l3 = level3_symbols(files, aliases, root) if l2["imported"] else \
        {"symbols": [], "note": "package not imported in first-party source"}

    per_cve = []
    descs = list(args.cve)
    if args.cve_desc:
        descs.append(["(unnamed)", args.cve_desc])
    for cve_id, desc in descs:
        named = cve_symbols(desc)
        m = level4_match(named, list(l3.get("symbols") or []),
                         list(l2.get("deep_import_symbols") or []))
        m["cve_id"] = cve_id
        m["priority"] = priority(l1, l2, m,
                                 actively_exploited=args.actively_exploited,
                                 ransomware=args.ransomware,
                                 severity=args.severity)
        per_cve.append(m)

    out = {
        "purl": args.purl,
        "ecosystem": eco,
        "package_name": name,
        "import_name": imp,
        "source_files_searched": len(files),
        "L1_dependency_path": l1,
        "L2_import_presence": l2,
        "L3_symbols_used": l3,
        "L4_cve_symbol_match": per_cve,
        "disclaimer": DISCLAIMER,
    }
    if not per_cve:
        out["overall_priority"] = priority(
            l1, l2, None,
            actively_exploited=args.actively_exploited,
            ransomware=args.ransomware, severity=args.severity)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
