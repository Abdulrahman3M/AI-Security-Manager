#!/usr/bin/env python3
"""ASM v0.1: offline, read-only baseline source review. Python 3.9+ standard library.

WARNING: Regex signals are NOT proof of vulnerabilities; this is not a complete SAST.
No target code is executed. The tool never includes matched secret values in reports.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

VERSION = "0.1.0"
IGNORE_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
    "dist", "build", "coverage", ".next", ".nuxt", ".gradle", ".idea",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "target",
    "bin", "obj", ".dart_tool", "Pods", ".terraform", ".asm-cache",
}
SKIP_SUFFIX = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
    ".gz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".a", ".o",
    ".class", ".jar", ".war", ".pyc", ".mp3", ".mp4", ".mov", ".woff",
    ".woff2", ".ttf", ".otf", ".db", ".sqlite", ".sqlite3", ".lockb",
}
KEY_ASSET_SUFFIX = {".p12", ".pfx", ".key"}
MAX_BYTES = 2_000_000
MAX_FILES = 50000

# These intentionally conservative line-based rules are review signals.
# Each tuple: id, title, category, severity, confidence, status, CWE, regex, remediation.
RULE_DEFS = [
    (
        "ASM001", "Possible hardcoded credential", "secrets", "high", "medium",
        "needs-validation", "CWE-798",
        r"""\b(?:api_key|secret_key|client_secret|access_token|password)\s*[:=]\s*["'][^"'\r\n]{8,}["']""",
        "Move privileged credentials to a secret store or server-side environment. "
        "Check whether the value is actually sensitive; revoke and rotate if exposed.",
    ),
    (
        "ASM002", "TLS certificate verification disabled", "transport", "high", "medium",
        "needs-validation", "CWE-295",
        r"""\bverify\s*=\s*False\b""",
        "Verify the call is an HTTPS client; enable certificate validation and trust a verified CA.",
    ),
    (
        "ASM003", "Node.js TLS validation disabled", "transport", "high", "high",
        "observed", "CWE-295",
        r"""NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0\b""",
        "Remove this setting and restore TLS certificate verification.",
    ),
    (
        "ASM004", "Database row-level security disabled", "database", "high", "high",
        "needs-validation", "CWE-862",
        r"""\bALTER\s+TABLE\b.*\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b""",
        "Confirm affected roles/API exposure, then enable RLS and write/test restrictive policies.",
    ),
    (
        "ASM005", "Flask development debug mode", "configuration", "medium", "medium",
        "needs-validation", "CWE-489",
        r"""\b(?:app|application)\.run\s*\([^)]*\bdebug\s*=\s*True\b""",
        "Do not enable development debug mode on publicly accessible production services.",
    ),
    (
        "ASM006", "Shell execution enabled", "injection", "medium", "low",
        "needs-validation", "CWE-78",
        r"""\bshell\s*=\s*True\b""",
        "Avoid shell=True where possible and pass fixed executable and argument arrays. "
        "Trace whether untrusted input reaches the command.",
    ),
    (
        "ASM007", "Python pickle deserialization", "deserialization", "medium", "medium",
        "needs-validation", "CWE-502",
        r"""\bpickle\.loads?\s*\(""",
        "Never unpickle untrusted input; use a safer format and validate inputs.",
    ),
    (
        "ASM008", "GitHub Actions action reference uses mutable version", "supply-chain",
        "low", "medium", "needs-validation", "CWE-829",
        r"""\buses:\s*[^\s#]+@(?:main|master|v\d+(?:\.\d+){0,2})\b""",
        "Pin third-party GitHub Actions to reviewed full commit SHAs and restrict permissions.",
    ),
    (
        "ASM009", "Supabase service-role key referenced in client source", "secrets",
        "high", "medium", "needs-validation", "CWE-798",
        r"""\b(?:SUPABASE_SERVICE_ROLE_KEY|service_role)\b""",
        "Check whether this code is browser-delivered. Keep service-role credentials server-side; "
        "their presence in trusted backend code alone is not a vulnerability.",
    ),
    (
        "ASM010", "Dynamic eval call (context required)", "code-execution", "medium",
        "low", "needs-validation", "CWE-95",
        r"""\beval\s*\(""",
        "Establish the data source and runtime semantics. Avoid evaluating untrusted strings as code.",
    ),
]
RULES = [(rid, title, category, severity, confidence, status, cwe,
          re.compile(pattern, re.IGNORECASE), remediation)
         for rid, title, category, severity, confidence, status, cwe, pattern, remediation
         in RULE_DEFS]

def finding(rule, relative_path, line_number):
    rid, title, category, severity, confidence, status, cwe, _regex, remediation = rule
    return {
        "id": f"{rid}:{relative_path}:{line_number}",
        "rule_id": rid,
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "path": relative_path,
        "line": line_number,
        "message": "A static source pattern indicates a possible issue; review context before confirming.",
        "remediation": remediation,
        "cwe": cwe,
        "evidence": "[redacted: source content not included]",
    }

def file_finding(rid, title, category, severity, confidence, path, remediation):
    return {
        "id": f"{rid}:{path}:1", "rule_id": rid, "title": title,
        "category": category, "severity": severity, "confidence": confidence,
        "status": "needs-validation", "path": path, "line": 1,
        "message": "A potentially sensitive file exists in the scanned tree; confirm repository exposure.",
        "remediation": remediation, "cwe": "CWE-200",
        "evidence": "[redacted: filename only]",
    }

def scan(root: Path):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Scan target must be a directory")
    findings = []
    stats = {
        "files_discovered": 0, "files_scanned": 0,
        "skipped_binary_or_unsupported": 0, "skipped_oversize": 0,
        "skipped_symlink": 0, "skipped_unreadable": 0,
        "truncated": False, "languages_detected": [],
    }
    suffixes = set()
    for folder, dirs, files in os.walk(root, topdown=True, followlinks=False):
        safe_dirs = []
        for name in sorted(dirs):
            p = Path(folder) / name
            if p.is_symlink():
                stats["skipped_symlink"] += 1
            elif name not in IGNORE_DIRS:
                safe_dirs.append(name)
        dirs[:] = safe_dirs
        for name in sorted(files):
            if stats["files_discovered"] >= MAX_FILES:
                stats["truncated"] = True
                break
            p = Path(folder) / name
            stats["files_discovered"] += 1
            if p.is_symlink():
                stats["skipped_symlink"] += 1
                continue
            rel = p.relative_to(root).as_posix()
            suffix = p.suffix.lower()
            if suffix:
                suffixes.add(suffix)
            if name == ".env" or (name.startswith(".env.") and
                                    not name.endswith((".example", ".sample", ".template"))):
                findings.append(file_finding(
                    "ASM011", "Environment file in project tree", "secrets",
                    "medium", "medium", rel,
                    "Ensure the real environment file is untracked, access-restricted and excluded "
                    "from deployment; rotate secrets if previously published.",
                ))
                # Do not inspect potentially real secret-file content.
                continue
            if suffix in KEY_ASSET_SUFFIX:
                findings.append(file_finding(
                    "ASM012", "Potential private-key material", "secrets",
                    "high", "medium", rel,
                    "Determine whether this is private material and whether it was committed; "
                    "move to secure storage and rotate if exposed.",
                ))
                continue
            if suffix in SKIP_SUFFIX:
                stats["skipped_binary_or_unsupported"] += 1
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    stats["skipped_oversize"] += 1
                    continue
                data = p.read_bytes()
                if b"\x00" in data[:4096]:
                    stats["skipped_binary_or_unsupported"] += 1
                    continue
                contents = data.decode("utf-8", errors="replace")
            except (OSError, PermissionError):
                stats["skipped_unreadable"] += 1
                continue
            stats["files_scanned"] += 1
            for number, line in enumerate(contents.splitlines(), start=1):
                if len(line) > 20000:
                    line = line[:20000]
                for rule in RULES:
                    rid = rule[0]
                    if rid == "ASM008" and not rel.startswith(".github/workflows/"):
                        continue
                    if rid == "ASM009" and suffix not in {".ts", ".tsx", ".js", ".jsx", ".html", ".vue", ".svelte"}:
                        continue
                    if rid == "ASM010" and suffix not in {".js", ".jsx", ".ts", ".tsx", ".py"}:
                        continue
                    if rule[7].search(line):
                        findings.append(finding(rule, rel, number))
        if stats["truncated"]:
            break
    stats["languages_detected"] = sorted(suffixes)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order[f["severity"]], f["path"], f["line"], f["rule_id"]))
    return {
        "tool": "AI Security Manager", "version": VERSION, "target": str(root),
        "summary": stats, "findings": findings,
        "limitations": [
            "Only selected line-based heuristics run; not comprehensive static analysis.",
            "No code execution, dynamic checks, exploit verification or database connections.",
            "AuthN/AuthZ, IDOR/BOLA and most RLS policy failures require contextual review/tests.",
            "Binary files, dependencies, ignored directories and oversize files are not fully reviewed.",
            "No finding is proof of exploitability and no findings does not mean secure.",
        ],
    }

def markdown(data):
    s = data["summary"]
    out = [
        "# AI Security Manager — Baseline Review", "",
        f"- Target: \`{data['target']}\`",
        f"- Engine: {data['tool']} {data['version']} (offline heuristics)",
        f"- Findings requiring triage: **{len(data['findings'])}**",
        f"- Files scanned: **{s['files_scanned']}** / {s['files_discovered']} discovered",
        f"- Skipped: binary/unsupported {s['skipped_binary_or_unsupported']}, "
        f"oversize {s['skipped_oversize']}, symlinks {s['skipped_symlink']}, "
        f"unreadable {s['skipped_unreadable']}",
        f"- Hit file limit: {'yes' if s['truncated'] else 'no'}",
        "", "## Findings", "",
    ]
    if not data["findings"]:
        out.append("No baseline patterns detected. **This does not establish security.**")
    for f in data["findings"]:
        out += [
            f"### {f['rule_id']} — {f['title']}",
            f"- Severity: **{f['severity']}** | Confidence: **{f['confidence']}** | "
            f"Status: **{f['status']}**",
            f"- Location: \`{f['path']}:{f['line']}\` | {f['cwe']}",
            f"- Evidence: {f['evidence']}",
            f"- Next action: {f['remediation']}", "",
        ]
    out += ["## Coverage and limitations", ""]
    out += [f"- {x}" for x in data["limitations"]]
    return "\n".join(out) + "\n"

def sarif(data):
    all_defs = RULE_DEFS + [
        ("ASM011", "Environment file in project tree", "secrets", "medium",
         "medium", "needs-validation", "CWE-200", "", "Secure environment files."),
        ("ASM012", "Potential private-key material", "secrets", "high",
         "medium", "needs-validation", "CWE-200", "", "Secure private keys."),
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": data["tool"], "version": data["version"],
                "informationUri": "https://github.com/Abdulrahman3M/AI-Security-Manager",
                "rules": [{"id": r[0], "shortDescription": {"text": r[1]},
                           "help": {"text": r[8]}} for r in all_defs],
            }},
            "results": [
                {
                    "ruleId": f["rule_id"],
                    "level": ("error" if f["severity"] in {"critical", "high"}
                              else "warning" if f["severity"] == "medium" else "note"),
                    "message": {"text": f["title"] + ". " + f["remediation"]},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": quote(f["path"], safe="/")},
                        "region": {"startLine": f["line"]},
                    }}],
                    "properties": {"confidence": f["confidence"], "status": f["status"],
                                   "category": f["category"]},
                } for f in data["findings"]
            ],
            "invocations": [{"executionSuccessful": True,
                             "properties": {"coverage": data["summary"],
                                            "limitations": data["limitations"]}}],
        }],
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description="AI Security Manager offline baseline audit")
    parser.add_argument("--version", action="version", version=VERSION)
    cmd = parser.add_subparsers(dest="command", required=True)
    scan_cmd = cmd.add_parser("scan", help="read-only scan of an authorized local folder")
    scan_cmd.add_argument("target", type=Path)
    scan_cmd.add_argument("--format", choices=["markdown", "json", "sarif"],
                          default="markdown")
    scan_cmd.add_argument("--output", type=Path, help="new report file (must not exist)")
    args = parser.parse_args(argv)
    try:
        report = scan(args.target)
        if args.format == "markdown":
            content = markdown(report)
        else:
            content = json.dumps(sarif(report) if args.format == "sarif" else report,
                                 indent=2, ensure_ascii=False) + "\n"
        if args.output is not None:
            dest = args.output.absolute()
            if dest.exists() or dest.is_symlink():
                raise ValueError("Refusing to overwrite an existing report file")
            with dest.open("x", encoding="utf-8") as stream:
                stream.write(content)
            print(f"Report saved: {dest}")
        else:
            print(content, end="")
        return 0
    except (OSError, ValueError) as error:
        print(f"ASM error: {error}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
