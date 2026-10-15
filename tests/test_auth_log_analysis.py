"""Tests for auth_log_analysis.py — pure parsing, no network."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ala", ROOT / "scripts" / "auth_log_analysis.py")
ala = importlib.util.module_from_spec(spec)
sys.modules["ala"] = ala
spec.loader.exec_module(ala)


def _brute(ip, n):
    return [
        f"Oct 15 10:0{i%6}:0{i%6} web01 sshd[441{i}]: "
        f"Failed password for invalid user user{i} from {ip} port 5123{i} ssh2"
        for i in range(n)
    ]


def test_brute_force_flagged():
    out = ala.analyze(_brute("198.51.100.23", 8), threshold=5)
    assert out["total_sources_flagged"] == 1
    f = out["findings"][0]
    assert f["src_ip"] == "198.51.100.23"
    assert f["failures"] == 8
    assert "brute-force" in f["flags"]
    assert f["severity"] == "high"


def test_brute_force_then_success_is_critical():
    lines = _brute("198.51.100.23", 8) + [
        "Oct 15 10:07:00 web01 sshd[4420]: Accepted password for deploy from 198.51.100.23 port 51260 ssh2"
    ]
    out = ala.analyze(lines, threshold=5)
    f = out["findings"][0]
    assert f["severity"] == "critical"
    assert "brute-force-then-success" in f["flags"]
    assert f["success_after_bruteforce_user"] == "deploy"
    assert "T1078" in f["attack_mapping"]


def test_below_threshold_not_flagged():
    out = ala.analyze(_brute("203.0.113.9", 3), threshold=5)
    assert out["total_sources_flagged"] == 0


def test_normal_success_not_flagged():
    lines = ["Oct 15 09:00:00 web01 sshd[100]: Accepted publickey for deploy from 203.0.113.9 port 2200 ssh2"]
    out = ala.analyze(lines, threshold=5)
    assert out["total_sources_flagged"] == 0


def test_findings_sorted_critical_first():
    lines = _brute("10.0.0.5", 6) + _brute("198.51.100.23", 6) + [
        "Oct 15 10:07:00 web01 sshd[4420]: Accepted password for root from 198.51.100.23 port 51260 ssh2"
    ]
    out = ala.analyze(lines, threshold=5)
    assert out["findings"][0]["severity"] == "critical"
    assert out["findings"][0]["src_ip"] == "198.51.100.23"
