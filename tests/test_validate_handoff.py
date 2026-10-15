"""Tests for validate_handoff.py — requires PyYAML (present in test venv/CI)."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vh", ROOT / "scripts" / "validate_handoff.py")
vh = importlib.util.module_from_spec(spec)
sys.modules["vh"] = vh
spec.loader.exec_module(vh)

pytest.importorskip("yaml")

GOOD = {
    "handoff": {
        "task_id": "CASE-1",
        "originating_agent": "security-analyst",
        "receiving_agent": "incident-responder",
        "created_at": "2026-10-15T11:42:00Z",
        "status": "open",
        "required_approval": "human-approval",
        "findings": [
            {"id": "F1", "confidence": "high", "basis": "observed",
             "evidence_refs": ["evidence/auth.log"]}
        ],
    }
}


def test_good_handoff_valid():
    assert vh.validate(GOOD) == []


def test_missing_required_field():
    bad = {"handoff": dict(GOOD["handoff"])}
    del bad["handoff"]["task_id"]
    assert any("task_id" in e for e in vh.validate(bad))


def test_bad_status():
    bad = {"handoff": dict(GOOD["handoff"], status="pending")}
    assert any("status" in e for e in vh.validate(bad))


def test_bad_approval():
    bad = {"handoff": dict(GOOD["handoff"], required_approval="maybe")}
    assert any("required_approval" in e for e in vh.validate(bad))


def test_finding_missing_confidence_and_evidence():
    bad = {"handoff": dict(GOOD["handoff"],
                           findings=[{"id": "F1", "basis": "observed"}])}
    errs = vh.validate(bad)
    assert any("confidence" in e for e in errs)
    assert any("evidence_refs" in e for e in errs)


def test_repo_example_handoff_is_valid():
    import yaml
    doc = yaml.safe_load((ROOT / "examples" / "handoff.yaml").read_text())
    assert vh.validate(doc) == []
