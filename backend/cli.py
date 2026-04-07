import asyncio
import argparse
import json
import sys
import os
from typing import Dict, Any
from engine import ScannerEngine

# ANSI colors for CLI
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

async def run_cli():
    parser = argparse.ArgumentParser(description="VulnPilot Headless CLI - AI-Powered Security Scanner")
    parser.add_argument("--target", required=True, help="Target URL, GitHub repo, or local directory")
    parser.add_argument("--session", help="Optional session cookie for authenticated scanning")
    parser.add_argument("--output", default="vulnpilot_report.md", help="Output file for the security report")
    parser.add_argument("--fail-on", default="High", choices=["Low", "Medium", "High", "Critical"], 
                        help="Exit with code 1 if findings of this severity or higher are found")
    parser.add_argument("--apply-fix", action="store_true", help="Automatically apply secure code fixes to the local codebase")
    
    args = parser.parse_args()

    severity_map = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    fail_threshold = severity_map.get(args.fail_on, 3)

    print(f"{Colors.BOLD}{Colors.HEADER}🚀 VulnPilot Security Scan Starting...{Colors.ENDC}")
    print(f"{Colors.OKCYAN}Target: {args.target}{Colors.ENDC}\n")

    max_severity_found = 0
    findings_list = []

    async def on_log(text: str, stage: str):
        color = Colors.OKBLUE
        if "ERROR" in text.upper(): color = Colors.FAIL
        elif "COMPLETE" in text.upper(): color = Colors.OKGREEN
        print(f"{color}[{stage.upper()}]{Colors.ENDC} {text}")

    async def on_finding(finding: Dict[str, Any]):
        nonlocal max_severity_found
        sev = finding.get("severity", "Low")
        sev_score = severity_map.get(sev, 1)
        if sev_score > max_severity_found:
            max_severity_found = sev_score
        
        color = Colors.OKGREEN
        if sev == "Critical": color = Colors.FAIL
        elif sev == "High": color = Colors.WARNING
        elif sev == "Medium": color = Colors.OKCYAN

        print(f"  {color}➜ [{sev.upper()}] {finding.get('vulnerability_type')}{Colors.ENDC} at {finding.get('url') or finding.get('url_pattern')}")
        findings_list.append(finding)

    engine = ScannerEngine(
        target=args.target,
        session_cookie=args.session,
        on_log=on_log,
        on_finding=on_finding
    )

    await engine.run()

    # Generate Markdown Report
    report_md = f"# 🛡️ VulnPilot Security Report\n\n"
    report_md += f"**Scanned Target:** `{args.target}`\n"
    report_md += f"**Max Severity:** {'🔴' if max_severity_found >= 3 else '🟡'} {args.fail_on if max_severity_found >= fail_threshold else 'Pass'}\n\n"
    report_md += "## 🚨 Vulnerability Summary\n\n"
    
    if not findings_list:
        report_md += "✅ No vulnerabilities detected.\n"
    else:
        for f in findings_list:
            report_md += f"### [{f.get('severity')}] {f.get('vulnerability_type')}\n"
            report_md += f"- **Location:** `{f.get('url') or f.get('url_pattern')}`\n"
            report_md += f"- **Risk:** {f.get('explanation')}\n"
            if f.get('remediation_code'):
                report_md += f"\n**🛡️ Secure Implementation:**\n```javascript\n{f.get('remediation_code')}\n```\n"
            report_md += "---\n"

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report_md)

    print(f"\n{Colors.BOLD}{Colors.OKGREEN}✅ Scan Complete! Report saved to {args.output}{Colors.ENDC}")

    if max_severity_found >= fail_threshold:
        print(f"{Colors.FAIL}❌ SECURITY GATE FAILED: Found vulnerabilities at or above {args.fail_on} severity.{Colors.ENDC}")
        sys.exit(1)
    else:
        print(f"{Colors.OKGREEN}🟢 SECURITY GATE PASSED.{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    try:
        asyncio.run(run_cli())
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user.")
        sys.exit(0)
