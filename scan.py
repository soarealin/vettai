#!/usr/bin/env python3
"""
VettAI - Security Scanner for AI Agent Skills
Scans SKILL.md and associated files for malicious patterns.

Usage:
    python3 scan.py --path ./some-skill/
    python3 scan.py --path ./some-skill/ --deep
    python3 scan.py --path ./some-skill/ --json
    python3 scan.py --audit ~/Projects/my-openclaw-workspace
"""

import argparse
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML not installed. Run: pip3 install pyyaml --break-system-packages")
    sys.exit(1)


# ─────────────────────────────────────────────
# DATA TYPES
# ─────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    name: str
    description: str
    line: int
    match: str
    file: str

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    skill_name: str
    skill_path: str
    risk_score: int
    verdict: str
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_ms: int = 0


# ─────────────────────────────────────────────
# SECURITY RULES
# ─────────────────────────────────────────────

RULES = [
    # ── SHELL INJECTION ──
    {
        "id": "SHELL-001",
        "severity": Severity.CRITICAL,
        "name": "Remote Code Execution via Pipe",
        "description": "Skill instructs to pipe remote content directly to a shell interpreter",
        "patterns": [
            r"curl\s+[^\n]*\|\s*(?:ba)?sh",
            r"wget\s+[^\n]*\|\s*(?:ba)?sh",
            r"curl\s+[^\n]*\|\s*python",
            r"eval\s*\(\s*\$\(curl",
        ],
    },
    {
        "id": "SHELL-002",
        "severity": Severity.CRITICAL,
        "name": "Base64 Encoded Command Execution",
        "description": "Skill uses base64 encoding to hide commands from plain-text review",
        "patterns": [
            r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d",
            r"base64\s+--decode\s*\|\s*(?:ba)?sh",
            r"python.*-c.*base64.*decode",
        ],
    },
    {
        "id": "SHELL-003",
        "severity": Severity.HIGH,
        "name": "Dangerous File Deletion",
        "description": "Skill contains recursive or forced file deletion commands",
        "patterns": [
            r"rm\s+-[rf]{2,}",
            r"rm\s+--force\s+--recursive",
            r"find\s+.*-delete",
            r"shred\s+",
        ],
    },
    {
        "id": "SHELL-004",
        "severity": Severity.HIGH,
        "name": "Privilege Escalation",
        "description": "Skill attempts to use elevated system privileges for dangerous operations",
        "patterns": [
            r"sudo\s+(?:rm|chmod|chown|mv|cp|dd|mkfs|kill|reboot|shutdown)",
            r"su\s+-\s+root",
            r"chmod\s+[0-7]*777",
            r"chmod\s+\+s\b",
            r"chown\s+root",
        ],
    },
    {
        "id": "SHELL-005",
        "severity": Severity.MEDIUM,
        "name": "Network Utility Usage",
        "description": "Skill uses raw network tools often associated with attacks",
        "patterns": [
            r"\bnc\s+-[a-z]*l",
            r"\bncat\s+",
            r"\bnetcat\s+",
            r"\bsocat\s+",
        ],
    },

    # ── MEMORY POISONING ──
    {
        "id": "MEM-001",
        "severity": Severity.CRITICAL,
        "name": "SOUL.md Modification",
        "description": "Skill attempts to modify the agent persona/system prompt file",
        "patterns": [
            r"(?:write|modify|edit|append|overwrite|update)\s.*SOUL\.md",
            r"echo\s+.*>+\s*.*SOUL\.md",
            r"sed\s+.*SOUL\.md",
            r"tee\s+.*SOUL\.md",
        ],
    },
    {
        "id": "MEM-002",
        "severity": Severity.CRITICAL,
        "name": "MEMORY.md Injection",
        "description": "Skill attempts to inject false memories into the agent",
        "patterns": [
            r"(?:write|modify|edit|append|overwrite)\s.*MEMORY\.md",
            r"echo\s+.*>+\s*.*MEMORY\.md",
            r"add.*memory.*instruction",
            r"inject.*into.*memory",
        ],
    },
    {
        "id": "MEM-003",
        "severity": Severity.HIGH,
        "name": "Agent Config Modification",
        "description": "Skill modifies openclaw.json or agent configuration files",
        "patterns": [
            r"(?:write|modify|edit)\s.*openclaw\.json",
            r"(?:write|modify|edit)\s.*clawdbot\.json",
            r"tools\.allow.*\*",
            r"security.*override",
        ],
    },

    # ── DATA EXFILTRATION ──
    {
        "id": "EXFIL-001",
        "severity": Severity.CRITICAL,
        "name": "Data Exfiltration via HTTP POST",
        "description": "Skill sends local file data to external servers",
        "patterns": [
            r"curl\s+(?:-X\s+POST\s+)?.*-d\s+.*\$\(cat",
            r"curl\s+.*--data.*@[/~]",
            r"wget\s+--post-file",
            r"python.*requests\.post.*open\(",
            r"curl.*-F\s+[\"']?file=@",
        ],
    },
    {
        "id": "EXFIL-002",
        "severity": Severity.HIGH,
        "name": "DNS Exfiltration",
        "description": "Skill might use DNS queries to leak data to external servers",
        "patterns": [
            r"nslookup.*\$\(",
            r"dig\s+.*\$\(",
            r"host\s+.*\$\(",
        ],
    },
    {
        "id": "EXFIL-003",
        "severity": Severity.HIGH,
        "name": "Known Malicious IP/Domain",
        "description": "Skill references infrastructure known from malware campaigns",
        "patterns": [
            r"91\.92\.242\.30",
            r"glot\.io/snip",
            r"(?:curl|wget|send|post).*paste(?:bin|\.ee|\.io)",
            r"(?:curl|wget|send|post).*ngrok\.io",
            r"(?:curl|wget|send|post).*serveo\.net",
        ],
    },

    # ── CREDENTIAL ACCESS ──
    {
        "id": "CRED-001",
        "severity": Severity.CRITICAL,
        "name": "SSH Key Access",
        "description": "Skill attempts to read SSH private keys",
        "patterns": [
            r"(?:cat|read|copy|cp|scp|curl.*file://)\s*.*\.ssh/id_",
            r"\.ssh/.*(?:private|key|pem)",
        ],
    },
    {
        "id": "CRED-002",
        "severity": Severity.CRITICAL,
        "name": "Environment File Exfiltration",
        "description": "Skill reads .env files and may exfiltrate secrets",
        "patterns": [
            r"cat\s+.*clawdbot/\.env",
            r"cat\s+.*openclaw/\.env",
            r"cat\s+.*\.env\s*\|",
            r"(?:curl|wget|send|post|upload).*\.env",
            r"\$\(cat\s+.*\.env\)",
        ],
    },
    {
        "id": "CRED-003",
        "severity": Severity.HIGH,
        "name": "Wallet / Crypto Key Access",
        "description": "Skill targets cryptocurrency wallet files, private keys, or seed phrases",
        "patterns": [
            r"(?:cat|read|copy|cp|open)\s+.*(?:wallet\.dat|keystore/)",
            r"(?:cat|read|copy|cp|open)\s+.*\.(?:bitcoin|ethereum|solana)",
            r"(?:cat|read|copy|cp|open)\s+.*seed.?phrase",
            r"(?:cat|read|export|dump)\s+.*(?:private.?key|mnemonic)",
            r"(?:cat|read|copy)\s+.*\.metamask",
        ],
    },
    {
        "id": "CRED-004",
        "severity": Severity.HIGH,
        "name": "Cloud Credential Access",
        "description": "Skill attempts to access cloud provider credentials",
        "patterns": [
            r"\.aws/credentials",
            r"\.gcloud/.*credentials",
            r"\.azure/.*token",
            r"\.kube/config",
        ],
    },

    # ── SUPPLY CHAIN ──
    {
        "id": "SUPPLY-001",
        "severity": Severity.HIGH,
        "name": "Suspicious Package Installation",
        "description": "Skill installs packages mimicking popular agent tools",
        "patterns": [
            r"npm\s+i(?:nstall)?\s+[a-z].*(?:openclaw|clawdbot|moltbot)",
            r"pip\s+install\s+.*--index-url",
            r"pip\s+install\s+.*--extra-index-url",
            r"gem\s+install\s+--source",
        ],
    },
    {
        "id": "SUPPLY-002",
        "severity": Severity.MEDIUM,
        "name": "Unverified Download and Execute",
        "description": "Skill downloads files and makes them executable without integrity checks",
        "patterns": [
            r"(?:curl|wget)\s+.*(?:\.exe|\.bin|\.dmg|\.pkg|\.appimage)\b",
            r"chmod\s+\+x\s+.*(?:downloaded|tmp|temp|\/tmp)",
            r"(?:curl|wget)\s+.*>\s*.*&&\s*chmod\s+\+x",
        ],
    },

    # ── PROMPT INJECTION ──
    {
        "id": "PI-001",
        "severity": Severity.HIGH,
        "name": "Hidden Unicode Characters",
        "description": "Skill contains invisible unicode characters that can hide instructions",
        "patterns": [
            r"[\u200b\u200c\u200d\u2060\ufeff]",
            r"[\u2066\u2067\u2068\u2069]",
            r"[\u202a\u202b\u202c\u202d\u202e]",
        ],
    },
    {
        "id": "PI-002",
        "severity": Severity.HIGH,
        "name": "Instruction Override Attempt",
        "description": "Skill contains phrases that try to override agent system instructions",
        "patterns": [
            r"ignore\s+(?:all\s+)?previous\s+instructions",
            r"disregard\s+(?:all\s+)?(?:prior|above)\s+",
            r"you\s+are\s+now\s+(?:a\s+)?(?:different|new)",
            r"system\s*:\s*you\s+(?:must|should|will)",
            r"<\s*system\s*>",
        ],
    },
    {
        "id": "PI-003",
        "severity": Severity.MEDIUM,
        "name": "Encoded Instructions",
        "description": "Skill contains encoded text that might hide malicious instructions",
        "patterns": [
            r"(?:decode|atob)\s*\(\s*[\"'][A-Za-z0-9+/=]{40,}",
            r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}",
        ],
    },
]


# ─────────────────────────────────────────────
# SCANNING LOGIC
# ─────────────────────────────────────────────

def scan_content(content, filepath):
    """Scan a single file's content against all rules."""
    findings = []
    lines = content.split("\n")

    for rule in RULES:
        for pattern in rule["patterns"]:
            try:
                for i, line in enumerate(lines, 1):
                    for match in re.finditer(pattern, line, re.IGNORECASE):
                        findings.append(
                            Finding(
                                rule_id=rule["id"],
                                severity=rule["severity"],
                                name=rule["name"],
                                description=rule["description"],
                                line=i,
                                match=match.group(0)[:100],
                                file=filepath,
                            )
                        )
            except re.error:
                pass

    return findings


def calculate_risk_score(findings):
    """Calculate risk score 0-100 and verdict string."""
    weights = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 1,
    }

    raw = sum(weights.get(f.severity, 0) for f in findings)
    score = min(100, round((1 - math.exp(-raw / 30)) * 100))

    if score == 0:
        verdict = "safe"
    elif score < 20:
        verdict = "low-risk"
    elif score < 50:
        verdict = "suspicious"
    elif score < 80:
        verdict = "dangerous"
    else:
        verdict = "malicious"

    return score, verdict


def scan_skill(skill_path, deep=False):
    """Scan an entire skill folder and return results."""
    start = time.time()
    path = Path(skill_path)

    # Find SKILL.md
    skill_md = path / "SKILL.md"
    if not skill_md.exists() or skill_md.is_dir():
        raise FileNotFoundError(f"No valid SKILL.md in {skill_path}")

    # Parse skill name from YAML frontmatter
    content = skill_md.read_text(encoding="utf-8")
    skill_name = "unknown"
    try:
        if content.startswith("---"):
            end = content.index("---", 3)
            fm = yaml.safe_load(content[3:end])
            if fm and isinstance(fm, dict):
                skill_name = str(fm.get("name", "unknown"))
    except (ValueError, yaml.YAMLError):
        pass

    all_findings = []
    files_scanned = 0

    # Always scan SKILL.md
    all_findings.extend(scan_content(content, "SKILL.md"))
    files_scanned += 1

    # Deep scan: also check scripts and other files
    if deep:
        scan_extensions = ["*.py", "*.sh", "*.js", "*.ts", "*.bash", "*.zsh", "*.rb"]
        for ext in scan_extensions:
            for f in path.rglob(ext):
                try:
                    file_content = f.read_text(encoding="utf-8")
                    rel_path = str(f.relative_to(path))
                    all_findings.extend(scan_content(file_content, rel_path))
                    files_scanned += 1
                except (UnicodeDecodeError, PermissionError):
                    pass

        # Also scan .md files in references/
        refs_dir = path / "references"
        if refs_dir.exists():
            for f in refs_dir.rglob("*.md"):
                try:
                    file_content = f.read_text(encoding="utf-8")
                    rel_path = str(f.relative_to(path))
                    all_findings.extend(scan_content(file_content, rel_path))
                    files_scanned += 1
                except (UnicodeDecodeError, PermissionError):
                    pass

    # Deduplicate (same rule + file + line)
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    score, verdict = calculate_risk_score(unique)
    duration = round((time.time() - start) * 1000)

    return ScanResult(
        skill_name=skill_name,
        skill_path=str(path),
        risk_score=score,
        verdict=verdict,
        findings=unique,
        files_scanned=files_scanned,
        scan_duration_ms=duration,
    )


# ─────────────────────────────────────────────
# OUTPUT FORMATTING
# ─────────────────────────────────────────────

VERDICT_DISPLAY = {
    "safe": "✅ SAFE",
    "low-risk": "🟡 LOW RISK",
    "suspicious": "🟠 SUSPICIOUS",
    "dangerous": "🔴 DANGEROUS",
    "malicious": "⛔ MALICIOUS",
}

SEVERITY_DISPLAY = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
    Severity.INFO: "ℹ️  INFO",
}


def format_terminal(result):
    """Format scan results for terminal output."""
    lines = [
        "",
        "🔍 VettAI Skill Scan Report",
        "═" * 50,
        "",
        f"  Skill:         {result.skill_name}",
        f"  Path:          {result.skill_path}",
        f"  Files scanned: {result.files_scanned}",
        f"  Duration:      {result.scan_duration_ms}ms",
        f"  Risk Score:    {result.risk_score}/100 — {VERDICT_DISPLAY[result.verdict]}",
        "",
    ]

    if not result.findings:
        lines.append("  No security issues found. ✅")
        lines.append("")
        return "\n".join(lines)

    # Group by severity
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        sev_findings = [f for f in result.findings if f.severity == severity]
        if not sev_findings:
            continue

        lines.append(f"  {SEVERITY_DISPLAY[severity]} ({len(sev_findings)})")
        lines.append("  " + "-" * 46)

        for f in sev_findings:
            lines.append(f"    [{f.rule_id}] {f.name}")
            lines.append(f"      File: {f.file}, Line: {f.line}")
            lines.append(f'      → "{f.match}"')
            lines.append("")

    # Recommendation
    lines.append("─" * 50)

    if result.verdict in ("malicious", "dangerous"):
        lines.append("  ⛔ RECOMMENDATION: DO NOT INSTALL THIS SKILL")
        has_clawhavoc = any(
            "91.92.242" in f.match or "glot.io" in f.match for f in result.findings
        )
        if has_clawhavoc:
            lines.append("  ⚠️  Matches ClawHavoc malware campaign patterns!")
    elif result.verdict == "suspicious":
        lines.append("  ⚠️  RECOMMENDATION: Review findings carefully before installing")
    elif result.verdict == "low-risk":
        lines.append("  🟡 RECOMMENDATION: Low risk, but review flagged items")
    else:
        lines.append("  ✅ RECOMMENDATION: Skill appears safe")

    lines.append("")
    return "\n".join(lines)


# ─────────────────────────────────────────────
# WORKSPACE AUDIT
# ─────────────────────────────────────────────

def audit_workspace(workspace_path, deep=False, as_json=False):
    """Scan all skills in an OpenClaw workspace."""
    path = Path(workspace_path)

    # Find all folders that contain a SKILL.md (works at any nesting depth)
    skill_folders = sorted(path.rglob("SKILL.md"))

    if not skill_folders:
        # Also try common fallback locations
        fallbacks = [Path.home() / ".openclaw" / "skills"]
        for fb in fallbacks:
            if fb.exists():
                skill_folders = sorted(fb.rglob("SKILL.md"))
                if skill_folders:
                    break

    if not skill_folders:
        print(f"Error: No SKILL.md files found in {workspace_path}", file=sys.stderr)
        sys.exit(1)

    print(f"\n🔍 VettAI Workspace Audit")
    print(f"  Scanning: {path}")
    print(f"  Found:    {len(skill_folders)} skills\n")

    all_results = []

    for skill_md in skill_folders:
        if skill_md.is_dir():
            continue
        skill_dir = skill_md.parent
        try:
            result = scan_skill(str(skill_dir), deep=deep)
            all_results.append(result)
        except Exception as e:
            if not as_json:
                print(f"  ⚠️  ERROR scanning {skill_dir.name}: {e}")

        if not as_json:
                # Compact one-line summary per skill
                icon = VERDICT_DISPLAY[result.verdict]
                print(f"  {icon:20s} {str(result.skill_name):30s} (score: {result.risk_score})")

    if as_json:
        output = [
            {
                "skill": r.skill_name,
                "path": r.skill_path,
                "score": r.risk_score,
                "verdict": r.verdict,
                "finding_count": len(r.findings),
                "findings": [f.to_dict() for f in r.findings],
            }
            for r in all_results
        ]
        print(json.dumps(output, indent=2))
    else:
        # Summary
        total = len(all_results)
        safe = sum(1 for r in all_results if r.risk_score == 0)
        low = sum(1 for r in all_results if 0 < r.risk_score < 20)
        suspicious = sum(1 for r in all_results if 20 <= r.risk_score < 50)
        dangerous = sum(1 for r in all_results if r.risk_score >= 50)

        print(f"\n{'═' * 50}")
        print(f"  Workspace Audit Summary")
        print(f"  {'─' * 40}")
        print(f"  Total Skills:   {total}")
        print(f"  ✅ Safe:         {safe}")
        print(f"  🟡 Low Risk:     {low}")
        print(f"  🟠 Suspicious:   {suspicious}")
        print(f"  🔴 Dangerous:    {dangerous}")

        if dangerous > 0:
            print(f"\n  ⚠️  {dangerous} skill(s) need immediate attention!")
            print(f"  Run with --deep for full analysis.")
        print()

    return all_results


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🔍 VettAI — Security Scanner for AI Agent Skills",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scan.py --path ./my-skill/           Scan a single skill
  python3 scan.py --path ./my-skill/ --deep    Scan skill + all scripts
  python3 scan.py --path ./my-skill/ --json    Output as JSON
  python3 scan.py --audit ~/.openclaw/skills   Audit all installed skills
        """,
    )

    parser.add_argument("--path", help="Path to a skill folder (must contain SKILL.md)")
    parser.add_argument("--audit", help="Audit all skills in a workspace/folder")
    parser.add_argument("--deep", action="store_true", help="Also scan scripts and reference files")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--version", action="version", version="VettAI 0.1.0")

    args = parser.parse_args()

    if not args.path and not args.audit:
        parser.print_help()
        sys.exit(0)

    if args.audit:
        results = audit_workspace(args.audit, deep=args.deep, as_json=args.json)
        worst = max((r.risk_score for r in results), default=0)
        sys.exit(1 if worst >= 50 else 0)
    else:
        try:
            result = scan_skill(args.path, deep=args.deep)
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        if args.json:
            output = {
                "skill_name": result.skill_name,
                "skill_path": result.skill_path,
                "risk_score": result.risk_score,
                "verdict": result.verdict,
                "files_scanned": result.files_scanned,
                "scan_duration_ms": result.scan_duration_ms,
                "findings": [f.to_dict() for f in result.findings],
            }
            print(json.dumps(output, indent=2))
        else:
            print(format_terminal(result))

        sys.exit(1 if result.risk_score >= 50 else 0)


if __name__ == "__main__":
    main()
