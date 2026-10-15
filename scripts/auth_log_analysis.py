#!/usr/bin/env python3
"""Analyze Linux auth logs (sshd) for brute force and suspicious logins.

Parses common OpenSSH auth messages from /var/log/auth.log (Debian/Kali) or
journald text, aggregates by source IP, and flags:
  * brute force           : failures from one IP >= --threshold
  * brute-force-then-success: failures >= threshold AND a later success from the
                              same IP (highest severity — possible compromise)
  * invalid-user spray    : many distinct invalid usernames from one IP

Read-only; treats log content as untrusted data (never executes it). stdlib only.

Usage:
  auth_log_analysis.py /var/log/auth.log
  cat auth.log | auth_log_analysis.py --threshold 10 --json

Exit: 0 analysis ran, 3 usage error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict

# Examples:
#  Failed password for invalid user admin from 198.51.100.23 port 51234 ssh2
#  Failed password for root from 198.51.100.23 port 51250 ssh2
#  Accepted password for deploy from 198.51.100.23 port 51260 ssh2
#  Accepted publickey for deploy from 203.0.113.9 port 2200 ssh2
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
INVALID_RE = re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)


def analyze(lines, threshold: int = 5) -> dict:
    fails = defaultdict(int)
    fail_users = defaultdict(set)
    invalid_users = defaultdict(set)
    successes = defaultdict(set)      # ip -> set(user)
    first_fail_line = {}
    success_after_fail = {}

    for i, line in enumerate(lines, 1):
        m = FAILED_RE.search(line)
        if m:
            ip = m.group("ip")
            fails[ip] += 1
            fail_users[ip].add(m.group("user"))
            first_fail_line.setdefault(ip, i)
            mi = INVALID_RE.search(line)
            if mi:
                invalid_users[ip].add(mi.group("user"))
            continue
        m = ACCEPTED_RE.search(line)
        if m:
            ip = m.group("ip")
            successes[ip].add(m.group("user"))
            if fails.get(ip, 0) >= threshold:
                success_after_fail[ip] = m.group("user")

    findings = []
    all_ips = set(fails) | set(successes)
    for ip in sorted(all_ips):
        f = fails.get(ip, 0)
        flags = []
        severity = "info"
        if ip in success_after_fail:
            flags.append("brute-force-then-success")
            severity = "critical"
        elif f >= threshold:
            flags.append("brute-force")
            severity = "high"
        if len(invalid_users.get(ip, ())) >= threshold:
            flags.append("invalid-user-spray")
            severity = "high" if severity == "info" else severity
        if not flags:
            continue
        findings.append({
            "src_ip": ip,
            "failures": f,
            "distinct_failed_users": sorted(fail_users.get(ip, ()))[:20],
            "distinct_invalid_users": len(invalid_users.get(ip, ())),
            "successful_users": sorted(successes.get(ip, ())),
            "success_after_bruteforce_user": success_after_fail.get(ip),
            "first_failure_line": first_fail_line.get(ip),
            "flags": flags,
            "severity": severity,
            "attack_mapping": ["T1110.001"] + (["T1078"] if ip in success_after_fail else []),
        })

    findings.sort(key=lambda x: {"critical": 0, "high": 1, "info": 2}[x["severity"]])
    return {
        "threshold": threshold,
        "total_sources_flagged": len(findings),
        "findings": findings,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="sshd auth-log brute-force analysis")
    ap.add_argument("files", nargs="*", help="auth log files; omit to read stdin")
    ap.add_argument("--threshold", type=int, default=5, help="failures to flag an IP")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.files:
        lines = []
        for p in args.files:
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    lines.extend(f.read().splitlines())
            except OSError as e:
                print(f"error reading {p}: {e}", file=sys.stderr)
                return 3
    else:
        lines = sys.stdin.read().splitlines()

    result = analyze(lines, threshold=args.threshold)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Flagged {result['total_sources_flagged']} source IP(s) "
              f"(threshold={result['threshold']}):")
        for f in result["findings"]:
            print(f"  [{f['severity'].upper()}] {f['src_ip']} "
                  f"failures={f['failures']} flags={','.join(f['flags'])}"
                  + (f" -> success as '{f['success_after_bruteforce_user']}'"
                     if f.get("success_after_bruteforce_user") else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
