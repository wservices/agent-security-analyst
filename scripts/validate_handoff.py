#!/usr/bin/env python3
"""Validate a cross-agent handoff.yaml against the platform schema expectations.

Checks the required top-level fields and per-finding discipline from
agents/platform/policies/HANDOFF-FORMAT.md:
  * handoff.task_id, originating_agent, receiving_agent, created_at, status
  * status in {open, in-progress, blocked, closed}
  * required_approval in {none, human-approval, authorization-record}
  * every findings[] entry has confidence in {high,medium,low} and
    basis in {observed,inferred,assumed}

Uses PyYAML when present; otherwise a minimal parser handles the flat subset.
Usage: validate_handoff.py handoff.yaml
Exit: 0 valid, 1 invalid, 3 usage/parse error.
"""
from __future__ import annotations

import sys

VALID_STATUS = {"open", "in-progress", "blocked", "closed"}
VALID_APPROVAL = {"none", "human-approval", "authorization-record"}
VALID_CONF = {"high", "medium", "low"}
VALID_BASIS = {"observed", "inferred", "assumed"}
REQUIRED = ["task_id", "originating_agent", "receiving_agent", "created_at", "status"]


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
    except ImportError:
        raise SystemExit(
            "validate_handoff requires PyYAML for full validation "
            "(pip install pyyaml / apt install python3-yaml)"
        )
    if not isinstance(data, dict):
        raise ValueError("handoff file is not a mapping")
    return data


def validate(doc: dict) -> list[str]:
    errs: list[str] = []
    h = doc.get("handoff", doc)  # allow top-level or nested under 'handoff:'
    if not isinstance(h, dict):
        return ["'handoff' is not a mapping"]
    for k in REQUIRED:
        if not h.get(k):
            errs.append(f"missing required field: {k}")
    if h.get("status") and h["status"] not in VALID_STATUS:
        errs.append(f"status '{h['status']}' not in {sorted(VALID_STATUS)}")
    appr = h.get("required_approval", "none")
    if appr not in VALID_APPROVAL:
        errs.append(f"required_approval '{appr}' not in {sorted(VALID_APPROVAL)}")
    findings = h.get("findings") or []
    if not isinstance(findings, list):
        errs.append("findings must be a list")
        findings = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            errs.append(f"findings[{i}] is not a mapping")
            continue
        if f.get("confidence") not in VALID_CONF:
            errs.append(f"findings[{i}].confidence must be one of {sorted(VALID_CONF)}")
        if f.get("basis") not in VALID_BASIS:
            errs.append(f"findings[{i}].basis must be one of {sorted(VALID_BASIS)}")
        if not f.get("evidence_refs"):
            errs.append(f"findings[{i}] has no evidence_refs")
    return errs


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: validate_handoff.py handoff.yaml", file=sys.stderr)
        return 3
    try:
        doc = load(argv[0])
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    errs = validate(doc)
    if errs:
        print("INVALID handoff:")
        for e in errs:
            print(f"  - {e}")
        return 1
    print("handoff OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
