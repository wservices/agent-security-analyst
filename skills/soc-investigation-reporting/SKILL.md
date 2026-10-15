---
name: soc-investigation-reporting
description: Produce a structured SOC investigation report.
version: 0.1.0
author: Pascal (pascal), Hermes Agent
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [soc, reporting, evidence, mitre, handoff]
    related_skills: [wazuh-alert-triage, ioc-extraction, security-reporting]
---

# SOC Investigation Reporting Skill

Assemble the findings, evidence, indicators, ATT&CK mapping, and recommended
actions of an investigation into a consistent, reproducible report plus a
machine-readable handoff. Enforces observation-vs-assumption labeling and
evidence references on every claim.

## When to Use

- Closing out or escalating a SOC investigation.
- Producing the artifact the Incident Responder or Team Lead consumes.
- **Don't use for:** the incident-response after-action report (Incident
  Responder owns that) — this is the analyst's investigation report.

## Prerequisites

- The case directory populated with evidence (alert JSON, logs, IOC output) and
  recorded timestamps/hashes.
- `templates/report.md` (in this skill) and `HANDOFF-FORMAT.md` from
  `agents/platform/policies`.

## How to Run

Fill `templates/report.md` from the case evidence, then emit `handoff.yaml` for
the next agent. The report is written text; the handoff is validated structure.

## Quick Reference

```
# validate the handoff you produced against the schema expectations
python3 scripts/validate_handoff.py handoff.yaml
```

## Procedure

1. **Summarize.** One paragraph: what happened, affected assets, disposition,
   confidence. Completion: readable without the appendices.
2. **Timeline (UTC).** Ordered events with source references. Completion: each
   row cites an evidence file + line/offset and a UTC timestamp with TZ noted.
3. **Findings.** Each finding labeled `observed | inferred | assumed`, with a
   confidence level and evidence refs (Security Policy rule 9). Completion: no
   unlabeled claims.
4. **Indicators.** Defanged IOC table with dispositions and enrichment sources.
   Completion: indicators match the `ioc-extraction` output; all defanged.
5. **ATT&CK mapping.** Technique ids with the evidence that supports each.
   Completion: every mapping is justified, not guessed.
6. **Recommendations & next action.** Concrete, with required approvals noted.
   Completion: each recommendation is actionable and attributed to an owner.
7. **Handoff.** Emit `handoff.yaml` per `HANDOFF-FORMAT.md`; validate it.
   Completion: `validate_handoff.py` passes and `required_approval` is set
   correctly for any intrusive/production action the receiver would take.

## Pitfalls

- **Unlabeled assumptions.** The most common defect — every claim states its
  basis and confidence.
- **Missing evidence refs.** A finding without a reproducible pointer is an
  opinion; attach the file+offset or stored API response.
- **Refanged indicators.** Never paste live malicious URLs/IPs into a shared
  report; keep them defanged.
- **Scope creep.** Report what the investigation found; recommend, do not
  perform, response actions.

## Verification

- `validate_handoff.py handoff.yaml` exits 0 (required fields present, confidence
  and basis set on findings).
- A reviewer can reproduce every finding from its evidence reference alone.
- The report contains: summary, UTC timeline, labeled findings, defanged IOCs,
  justified ATT&CK mapping, recommendations.
