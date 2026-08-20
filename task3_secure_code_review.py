"""
TASK 3: Secure Coding Review
--------------------------------
A simple static code analyzer that scans a Python (or JS) source file
for common security vulnerabilities using pattern (regex) matching —
similar in spirit to how basic static analyzers work.

It reports findings with severity, line number, description, and a
recommended fix, then documents everything to a report file.

Key concepts used: file handling, regular expressions (re), functions,
lists/dictionaries, string formatting

HOW TO RUN:
    python3 task3_secure_code_review.py <path_to_file_to_review>

    If no file is given, it reviews the bundled sample file
    "sample_vulnerable_code.py" (created automatically) so you can
    see the tool working immediately.
"""

import re
import sys
import os
from datetime import datetime

# Each rule: (name, regex pattern, severity, description, fix)
RULES = [
    (
        "Hardcoded password/secret",
        r"(?i)(password|secret|api_key|token)\s*=\s*[\"'][^\"']{3,}[\"']",
        "HIGH",
        "A password, secret key, or API token appears to be hardcoded directly in source code.",
        "Load secrets from environment variables or a secrets manager instead of hardcoding them (e.g. os.environ['API_KEY']).",
    ),
    (
        "SQL query built with string concatenation/formatting",
        r"(?i)(select|insert|update|delete)\s+.+(\+|%s|\.format\(|f[\"'])",
        "CRITICAL",
        "SQL queries built via string concatenation or f-strings can allow SQL Injection if user input reaches this string.",
        "Use parameterized queries / prepared statements (e.g. cursor.execute(query, params)) instead of building SQL with string concatenation.",
    ),
    (
        "Use of eval()",
        r"\beval\s*\(",
        "CRITICAL",
        "eval() executes arbitrary code from a string, which is extremely dangerous if the input isn't fully trusted.",
        "Avoid eval(). Use ast.literal_eval() for safely parsing literals, or a dedicated parser for the expected input format.",
    ),
    (
        "Use of exec()",
        r"\bexec\s*\(",
        "CRITICAL",
        "exec() runs arbitrary Python code from a string and can lead to remote code execution if input is attacker-controlled.",
        "Avoid exec() entirely for anything touching user input; redesign the logic to not require dynamic code execution.",
    ),
    (
        "os.system() / shell command execution",
        r"os\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True",
        "HIGH",
        "Running shell commands built from strings (especially with shell=True) can allow command injection.",
        "Use subprocess.run([...], shell=False) with a list of arguments instead of a shell string, and never interpolate user input directly.",
    ),
    (
        "Insecure deserialization (pickle)",
        r"pickle\.loads?\s*\(",
        "HIGH",
        "Unpickling data from an untrusted source can execute arbitrary code during deserialization.",
        "Avoid pickle for untrusted data. Use a safe format like JSON, or validate/sign the data before unpickling.",
    ),
    (
        "Weak hashing algorithm for sensitive data",
        r"hashlib\.(md5|sha1)\s*\(",
        "MEDIUM",
        "MD5 and SHA-1 are cryptographically broken and unsuitable for passwords or security-sensitive hashing.",
        "Use a password-hashing algorithm like bcrypt, scrypt, or argon2 for passwords, or SHA-256+ for general integrity hashing.",
    ),
    (
        "TLS/SSL certificate verification disabled",
        r"verify\s*=\s*False",
        "HIGH",
        "Disabling certificate verification allows man-in-the-middle attacks on HTTPS connections.",
        "Never set verify=False in production. Fix the underlying certificate issue instead, or pin a trusted CA bundle.",
    ),
    (
        "Debug mode enabled",
        r"(?i)debug\s*=\s*True",
        "MEDIUM",
        "Running an application in debug mode in production can leak stack traces, source code, and internal config to users.",
        "Ensure DEBUG is set to False in production, typically driven by an environment variable.",
    ),
    (
        "Assert used for security checks",
        r"^\s*assert\s+",
        "LOW",
        "assert statements are stripped out when Python runs with the -O optimization flag, so they should never be relied on for security checks.",
        "Use explicit if-checks that raise an exception, instead of assert, for anything security-relevant.",
    ),
]


SAMPLE_CODE = '''\
import os
import pickle
import hashlib
import requests

API_KEY = "sk_live_12345SUPER_SECRET_KEY"
DEBUG = True

def get_user(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    return db.execute(query)

def run_admin_command(cmd):
    os.system(cmd)

def load_session(data):
    return pickle.loads(data)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def fetch_data(url):
    return requests.get(url, verify=False)

def calculate(expression):
    return eval(expression)
'''


def scan_file(filepath):
    """Read a source file and check every line against every rule."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    findings = []
    for line_number, line in enumerate(lines, start=1):
        for rule_name, pattern, severity, description, fix in RULES:
            if re.search(pattern, line):
                findings.append({
                    "line": line_number,
                    "code": line.strip(),
                    "rule": rule_name,
                    "severity": severity,
                    "description": description,
                    "fix": fix,
                })
    return findings


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def calculate_score(findings):
    """A simple deducted-points score out of 100 based on severity counts."""
    penalty = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 6, "LOW": 2}
    score = 100
    for f in findings:
        score -= penalty.get(f["severity"], 0)
    return max(score, 0)


def print_report(filepath, findings):
    print("=" * 60)
    print(f" SECURE CODE REVIEW REPORT")
    print(f" File: {filepath}")
    print(f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if not findings:
        print("\nNo issues found by the current rule set. ✅")
        return

    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\nTotal findings: {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in counts:
            print(f"  {sev:<9}: {counts[sev]}")

    score = calculate_score(findings)
    print(f"\nSecurity Score: {score}/100")

    print("\n" + "-" * 60)
    print("DETAILED FINDINGS")
    print("-" * 60)

    for i, f in enumerate(findings_sorted, start=1):
        print(f"\n[{i}] {f['rule']}  —  {f['severity']}")
        print(f"    Line {f['line']}: {f['code']}")
        print(f"    Issue: {f['description']}")
        print(f"    Recommended fix: {f['fix']}")

    print("\n" + "=" * 60)


def save_report_to_file(filepath, findings):
    """Write the findings out to a text report file (documenting the audit)."""
    score = calculate_score(findings)
    report_name = "secure_code_review_report.txt"

    with open(report_name, "w", encoding="utf-8") as f:
        f.write("SECURE CODE REVIEW REPORT\n")
        f.write(f"File reviewed: {filepath}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Security Score: {score}/100\n")
        f.write(f"Total findings: {len(findings)}\n")
        f.write("=" * 60 + "\n\n")

        findings_sorted = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        for i, finding in enumerate(findings_sorted, start=1):
            f.write(f"[{i}] {finding['rule']} — {finding['severity']}\n")
            f.write(f"    Line {finding['line']}: {finding['code']}\n")
            f.write(f"    Issue: {finding['description']}\n")
            f.write(f"    Recommended fix: {finding['fix']}\n\n")

    print(f"\nFull report saved to: {report_name}")


def main():
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return
    else:
        # No file given — create and scan the bundled sample so the tool
        # is immediately demonstrable during a viva.
        filepath = "sample_vulnerable_code.py"
        if not os.path.exists(filepath):
            with open(filepath, "w") as f:
                f.write(SAMPLE_CODE)
        print(f"No file argument given — scanning bundled sample: {filepath}\n")

    findings = scan_file(filepath)
    print_report(filepath, findings)
    save_report_to_file(filepath, findings)


if __name__ == "__main__":
    main()
