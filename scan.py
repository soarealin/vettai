#!/usr/bin/env python3
"""
VettAI - Security Scanner for AI Agent Skills
Scans SKILL.md and associated files for malicious patterns.
Uses optional AI analysis for deep behavioral threat detection.

Usage:
    python3 scan.py --path ./some-skill/
    python3 scan.py --path ./some-skill/ --deep
    python3 scan.py --path ./some-skill/ --ai
    python3 scan.py --path ./some-skill/ --json
    python3 scan.py --audit ~/Projects/my-openclaw-workspace
    python3 scan.py --audit ./skills/ --export-threats threats.json
"""

import argparse
import json
import math
import os
import re
import sys
import time
import urllib.request
import urllib.error
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

# Pre-compile all regex patterns once at import time (massive speedup)
COMPILED_RULES = []
for rule in RULES:
    compiled_patterns = []
    for p in rule["patterns"]:
        try:
            compiled_patterns.append(re.compile(p, re.IGNORECASE))
        except re.error:
            pass
    COMPILED_RULES.append({
        "id": rule["id"],
        "severity": rule["severity"],
        "name": rule["name"],
        "description": rule["description"],
        "compiled": compiled_patterns,
    })


def scan_content(content, filepath):
    """Scan a single file's content against all rules."""
    findings = []
    lines = content.split("\n")

    for rule in COMPILED_RULES:
        for pattern in rule["compiled"]:
            for i, line in enumerate(lines, 1):
                for match in pattern.finditer(line):
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
# AI ANALYSIS ENGINE
# ─────────────────────────────────────────────

AI_SYSTEM_PROMPT = """You are VettAI, a security analyst specialized in AI agent skills.
You analyze SKILL.md files for security threats. Be concise and specific.

Evaluate the skill for these threat categories:
1. DATA EXFILTRATION - Does it send local files, secrets, or credentials to external servers?
2. REMOTE CODE EXECUTION - Does it download and execute code from the internet?
3. MEMORY POISONING - Does it modify SOUL.md, MEMORY.md, or agent configuration?
4. CREDENTIAL THEFT - Does it access SSH keys, .env files, wallets, or cloud credentials?
5. PROMPT INJECTION - Does it try to override agent instructions or hide commands?
6. SUPPLY CHAIN - Does it install suspicious packages or download unverified binaries?
7. OBFUSCATION - Does it use encoding, unicode tricks, or indirection to hide intent?

Also look for SUBTLE threats that regex cannot catch:
- Innocent-looking instructions that chain together into an attack
- Social engineering ("run this to fix a bug" that actually steals data)
- Conditional logic that behaves differently in certain environments
- Legitimate-looking URLs that are actually malicious

Respond in this exact JSON format:
{
  "risk_level": "safe|low|suspicious|dangerous|malicious",
  "confidence": 0.0-1.0,
  "summary": "One sentence summary of the overall risk",
  "threats": [
    {
      "category": "category name",
      "severity": "critical|high|medium|low",
      "description": "What the threat does",
      "evidence": "The specific text/line that is suspicious",
      "why_dangerous": "Why this is a real threat, not a false positive"
    }
  ],
  "subtle_findings": "Any concerns that pure regex would miss",
  "recommendation": "What the user should do"
}"""


def ai_analyze(content, api_key, model="claude-sonnet-4-20250514"):
    """Send skill content to Claude API for deep behavioral analysis."""

    request_body = json.dumps({
        "model": model,
        "max_tokens": 2000,
        "messages": [
            {"role": "user", "content": f"Analyze this SKILL.md file for security threats:\n\n```\n{content[:15000]}\n```"}
        ],
        "system": AI_SYSTEM_PROMPT,
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=request_body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["content"][0]["text"]

            # Extract JSON from response (handle markdown code blocks)
            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                if text.endswith("```"):
                    text = text[:-3]
            text = text.strip()

            return json.loads(text)

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        if e.code == 401:
            return {"error": "Invalid API key. Check your ANTHROPIC_API_KEY."}
        elif e.code == 429:
            return {"error": "Rate limited. Wait a moment and try again."}
        else:
            return {"error": f"API error {e.code}: {error_body[:200]}"}
    except urllib.error.URLError as e:
        return {"error": f"Network error: {e.reason}"}
    except json.JSONDecodeError:
        return {"error": "Could not parse AI response as JSON."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


def format_ai_report(ai_result):
    """Format AI analysis results for terminal output."""
    lines = []

    if "error" in ai_result:
        lines.append(f"\n  ⚠️  AI Analysis Error: {ai_result['error']}")
        return "\n".join(lines)

    risk = ai_result.get("risk_level", "unknown")
    confidence = ai_result.get("confidence", 0)
    summary = ai_result.get("summary", "No summary available.")

    risk_icons = {
        "safe": "✅", "low": "🟡", "suspicious": "🟠",
        "dangerous": "🔴", "malicious": "⛔",
    }
    icon = risk_icons.get(risk, "❓")

    lines.append("")
    lines.append("  🤖 AI DEEP ANALYSIS (powered by Claude)")
    lines.append("  " + "═" * 46)
    lines.append(f"  Risk:       {icon} {risk.upper()} (confidence: {confidence:.0%})")
    lines.append(f"  Summary:    {summary}")

    threats = ai_result.get("threats", [])
    if threats:
        lines.append("")
        lines.append(f"  AI-detected threats ({len(threats)}):")
        lines.append("  " + "-" * 46)
        for t in threats:
            sev = t.get("severity", "medium").upper()
            cat = t.get("category", "unknown")
            desc = t.get("description", "")
            why = t.get("why_dangerous", "")
            lines.append(f"    [{sev}] {cat}")
            lines.append(f"      {desc}")
            if why:
                lines.append(f"      → {why}")
            lines.append("")

    subtle = ai_result.get("subtle_findings", "")
    if subtle and subtle.lower() not in ("none", "n/a", "none found", ""):
        lines.append("  🔎 Subtle findings (regex would miss):")
        lines.append(f"     {subtle}")
        lines.append("")

    rec = ai_result.get("recommendation", "")
    if rec:
        lines.append(f"  💡 AI Recommendation: {rec}")
        lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────
# THREAT DATABASE
# ─────────────────────────────────────────────

def export_threat_database(results, output_path):
    """Export dangerous skills as a threat intelligence database."""
    threats = []

    for r in results:
        if r.risk_score < 20:
            continue

        threat_entry = {
            "skill_name": str(r.skill_name),
            "skill_path": r.skill_path,
            "risk_score": r.risk_score,
            "verdict": r.verdict,
            "scan_date": time.strftime("%Y-%m-%d"),
            "finding_count": len(r.findings),
            "categories": list(set(
                f.rule_id.split("-")[0] for f in r.findings
            )),
            "rule_ids": list(set(f.rule_id for f in r.findings)),
            "critical_count": sum(
                1 for f in r.findings if f.severity == Severity.CRITICAL
            ),
            "high_count": sum(
                1 for f in r.findings if f.severity == Severity.HIGH
            ),
            "indicators": [],
            "findings": [],
        }

        # Extract indicators of compromise (IoCs)
        # Known-legitimate domains (not IoCs even if in suspicious skills)
        LEGIT_DOMAINS = {
            # Code hosting & CDNs
            "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
            "npmjs.com", "npmjs.org", "pypi.org", "crates.io",
            # Dev tools & package managers
            "brew.sh", "astral.sh", "rust-lang.org", "go.dev",
            "nodejs.org", "python.org", "deno.land", "bun.sh",
            "cursor.com", "opencode.dev",
            # AI platforms (legitimate)
            "anthropic.com", "openai.com", "ollama.com", "huggingface.co",
            "openclaw.ai", "parallel.ai", "vapi.ai",
            # Cloud & infra
            "docker.com", "docker.io", "tailscale.com", "fly.io",
            "google.com", "googleapis.com", "cloudflare.com",
            "microsoft.com", "azure.com", "aws.amazon.com",
            "vercel.com", "netlify.com", "heroku.com",
            # Reference & knowledge
            "stackoverflow.com", "reddit.com", "wikipedia.org",
            # Blockchain tools (legit, used by legit crypto skills)
            "paradigm.xyz", "foundry.paradigm.xyz",
            # Shell script hosts (legit)
            "inference.sh", "install.sh",
            # Other
            "example.com", "localhost",
        }

        for f in r.findings:
            # Extract IPs
            ips = re.findall(r"\d+\.\d+\.\d+\.\d+", f.match)
            for ip in ips:
                if ip not in [i["value"] for i in threat_entry["indicators"]]:
                    threat_entry["indicators"].append({
                        "type": "ip", "value": ip
                    })

            # Extract domains from URLs (full hostname)
            # Pattern 1: Full URLs with https:// or www.
            urls = re.findall(
                r"(?:https?://|www\.)((?:[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\.)+[a-z]{2,})",
                f.match, re.I
            )
            # Pattern 2: Bare domains followed by a path (e.g. glot.io/snip/abc)
            bare_domains = re.findall(
                r"(?<![a-z0-9/._-])((?:[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\.)+(?:com|net|org|io|dev|ai|co|app|xyz))/",
                f.match, re.I
            )
            for raw_domain in urls + bare_domains:
                d_lower = raw_domain.lower().rstrip(".")
                # Skip known-legitimate domains
                if any(d_lower == leg or d_lower.endswith("." + leg) for leg in LEGIT_DOMAINS):
                    continue
                if d_lower not in [i["value"] for i in threat_entry["indicators"]]:
                    threat_entry["indicators"].append({
                        "type": "domain", "value": d_lower
                    })

            threat_entry["findings"].append({
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "name": f.name,
                "file": f.file,
                "line": f.line,
                "match": f.match,
            })

        threats.append(threat_entry)

    # Sort by risk score (most dangerous first)
    threats.sort(key=lambda x: x["risk_score"], reverse=True)

    # Build database
    db = {
        "vettai_version": "0.1.0",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_scanned": len(results),
        "total_threats": len(threats),
        "summary": {
            "malicious": sum(1 for t in threats if t["risk_score"] >= 80),
            "dangerous": sum(1 for t in threats if 50 <= t["risk_score"] < 80),
            "suspicious": sum(1 for t in threats if 20 <= t["risk_score"] < 50),
        },
        "top_iocs": _extract_top_iocs(threats),
        "threats": threats,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

    return db


def _extract_top_iocs(threats):
    """Extract and rank indicators of compromise across all threats."""
    from collections import Counter
    ioc_counter = Counter()

    for t in threats:
        for ioc in t["indicators"]:
            ioc_counter[f"{ioc['type']}:{ioc['value']}"] += 1

    return [
        {"type": k.split(":")[0], "value": k.split(":", 1)[1], "seen_in": v}
        for k, v in ioc_counter.most_common(50)
    ]


# ─────────────────────────────────────────────
# WORKSPACE AUDIT
# ─────────────────────────────────────────────

def _scan_skill_safe(args):
    """Wrapper for multiprocessing — returns (result, error)."""
    skill_dir, deep = args
    try:
        return scan_skill(str(skill_dir), deep=deep), None
    except Exception as e:
        return None, (skill_dir.name, str(e))


def audit_workspace(workspace_path, deep=False, as_json=False):
    """Scan all skills in an OpenClaw workspace."""
    from multiprocessing import Pool, cpu_count

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

    # Filter out directories
    skill_dirs = [sm.parent for sm in skill_folders if not sm.is_dir()]
    num_workers = min(cpu_count(), 8)

    print(f"\n🔍 VettAI Workspace Audit")
    print(f"  Scanning: {path}")
    print(f"  Found:    {len(skill_dirs)} skills ({num_workers} workers)\n")

    all_results = []
    start = time.time()

    # Parallel scan
    with Pool(processes=num_workers) as pool:
        tasks = [(sd, deep) for sd in skill_dirs]
        for result, error in pool.imap_unordered(_scan_skill_safe, tasks, chunksize=50):
            if error and not as_json:
                print(f"  ⚠️  ERROR scanning {error[0]}: {error[1]}")
            if result:
                all_results.append(result)

    elapsed = time.time() - start

    # Sort by risk score descending for display
    all_results.sort(key=lambda r: r.risk_score, reverse=True)

    if not as_json:
        for result in all_results:
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
        print(f"  ⏱️  Duration:     {elapsed:.1f}s ({total / max(elapsed, 0.1):.0f} skills/sec)")

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
  python3 scan.py --path ./my-skill/ --ai      Scan + AI deep analysis
  python3 scan.py --path ./my-skill/ --smart   Regex first, AI only if suspicious
  python3 scan.py --path ./my-skill/ --json    Output as JSON
  python3 scan.py --audit ~/.openclaw/skills   Audit all installed skills
  python3 scan.py --audit ./skills/ --export-threats threats.json
  python3 scan.py --audit ./skills/ --smart    Smart audit with AI for risky skills
        """,
    )

    parser.add_argument("--path", help="Path to a skill folder (must contain SKILL.md)")
    parser.add_argument("--audit", help="Audit all skills in a workspace/folder")
    parser.add_argument("--deep", action="store_true", help="Also scan scripts and reference files")
    parser.add_argument("--ai", action="store_true", help="Enable AI deep analysis (requires ANTHROPIC_API_KEY)")
    parser.add_argument("--smart", action="store_true",
                        help="Smart mode: regex first, AI only for suspicious+ skills (saves cost)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview what --smart/--ai would do without calling the API (no cost)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--export-threats", metavar="FILE", help="Export threat database to JSON file")
    parser.add_argument("--version", action="version", version="VettAI 0.1.0")

    args = parser.parse_args()

    if not args.path and not args.audit:
        parser.print_help()
        sys.exit(0)

    # Check for API key if AI mode requested (skip check for dry-run)
    api_key = None
    if (args.ai or args.smart) and not args.dry_run:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            flag = "--smart" if args.smart else "--ai"
            print(f"Error: {flag} requires ANTHROPIC_API_KEY environment variable.", file=sys.stderr)
            print("  Get a key at: https://console.anthropic.com/settings/keys", file=sys.stderr)
            print("  Then run: export ANTHROPIC_API_KEY=sk-ant-...", file=sys.stderr)
            sys.exit(1)

    if args.audit:
        results = audit_workspace(args.audit, deep=args.deep, as_json=args.json)

        # Smart audit: run AI only on suspicious+ skills
        if (args.smart or args.dry_run) and (api_key or args.dry_run):
            risky = [r for r in results if r.risk_score >= 20]
            safe_count = len(results) - len(risky)

            if args.dry_run:
                # Show what WOULD happen without calling the API
                print(f"\n  🧪 DRY RUN — no API calls, no cost")
                print(f"  {'═' * 46}")
                print(f"  Total skills scanned:      {len(results)}")
                print(f"  ✅ Safe (AI skipped):        {safe_count}")
                print(f"  🔍 Would send to AI:        {len(risky)}")
                print(f"  💰 Estimated cost:          ~${len(risky) * 0.02:.2f}")
                print(f"     (vs ${len(results) * 0.02:.2f} without --smart)")
                print(f"     Savings:                 ~${safe_count * 0.02:.2f} ({safe_count} skipped)")
                if risky:
                    print(f"\n  Skills that would trigger AI analysis:")
                    print(f"  {'─' * 46}")
                    for r in sorted(risky, key=lambda x: x.risk_score, reverse=True)[:25]:
                        icon = VERDICT_DISPLAY[r.verdict]
                        print(f"    {icon} {str(r.skill_name):30s} score: {r.risk_score}")
                    if len(risky) > 25:
                        print(f"    ... and {len(risky) - 25} more")
                print(f"\n  ✅ Ready? Remove --dry-run to run for real.")
                print()
            elif risky:
                print(f"\n  🤖 Smart mode: AI analyzing {len(risky)} suspicious skills")
                print(f"     (skipping {len(results) - len(risky)} safe skills — saving ~${(len(results) - len(risky)) * 0.02:.2f})")
                print()
                for i, r in enumerate(risky, 1):
                    skill_md = Path(r.skill_path) / "SKILL.md"
                    try:
                        content = skill_md.read_text(encoding="utf-8")
                        print(f"  [{i}/{len(risky)}] Analyzing {r.skill_name}...", end="", flush=True)
                        ai_result = ai_analyze(content, api_key)
                        print(" done.")
                        if "error" not in ai_result:
                            ai_risk = ai_result.get("risk_level", "unknown")
                            ai_conf = ai_result.get("confidence", 0)
                            threats = len(ai_result.get("threats", []))
                            print(f"         AI: {ai_risk.upper()} ({ai_conf:.0%}) — {threats} threat(s)")
                    except Exception as e:
                        print(f" error: {e}")
                print(f"\n  💰 Cost: ~${len(risky) * 0.02:.2f} ({len(risky)} AI scans)")
                print(f"     Saved: ~${(len(results) - len(risky)) * 0.02:.2f} ({len(results) - len(risky)} skipped)")
                print()

        # Export threat database if requested
        if args.export_threats:
            db = export_threat_database(results, args.export_threats)
            print(f"\n  📦 Threat database exported: {args.export_threats}")
            print(f"     {db['total_threats']} threats, {len(db['top_iocs'])} IoCs")
            print()

        worst = max((r.risk_score for r in results), default=0)
        sys.exit(1 if worst >= 50 else 0)
    else:
        try:
            result = scan_skill(args.path, deep=args.deep)
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        # AI analysis: always with --ai, only if suspicious with --smart
        ai_result = None
        run_ai = False

        if args.dry_run:
            # Show what would happen
            would_run = False
            if args.ai:
                would_run = True
            elif args.smart:
                would_run = result.risk_score >= 20

            print(format_terminal(result))
            print(f"  🧪 DRY RUN — no API calls, no cost")
            print(f"  {'═' * 46}")
            if would_run:
                skill_md = Path(args.path) / "SKILL.md"
                content = skill_md.read_text(encoding="utf-8")
                tokens = len(content) // 4  # rough estimate
                print(f"  Would send to AI:    YES")
                print(f"  Reason:              Score {result.risk_score} ≥ 20 (suspicious)")
                print(f"  Estimated tokens:    ~{tokens:,} input + ~1,000 output")
                print(f"  Estimated cost:      ~$0.02")
            else:
                print(f"  Would send to AI:    NO")
                print(f"  Reason:              Score {result.risk_score} < 20 (safe)")
                print(f"  Cost:                $0.00")
            print(f"\n  ✅ Ready? Remove --dry-run to run for real.")
            print()
            sys.exit(1 if result.risk_score >= 50 else 0)

        if args.ai and api_key:
            run_ai = True
        elif args.smart and api_key:
            if result.risk_score >= 20:
                run_ai = True
            else:
                if not args.json:
                    print(f"  🤖 Smart mode: Score {result.risk_score} < 20 — AI analysis skipped (saving ~$0.02)")
                    print()

        if run_ai:
            skill_md = Path(args.path) / "SKILL.md"
            content = skill_md.read_text(encoding="utf-8")
            if not args.json:
                print("\n  🤖 Running AI analysis...", end="", flush=True)
            ai_result = ai_analyze(content, api_key)
            if not args.json:
                print(" done.\n")

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
            if ai_result:
                output["ai_analysis"] = ai_result
            print(json.dumps(output, indent=2))
        else:
            print(format_terminal(result))
            if ai_result:
                print(format_ai_report(ai_result))

        sys.exit(1 if result.risk_score >= 50 else 0)


if __name__ == "__main__":
    main()
