# SOC Investigation Report — <CASE-ID>

- **Analyst:** <agent/role>
- **Opened (UTC):** <timestamp>   **Closed (UTC):** <timestamp>
- **Disposition:** false-positive | benign-expected | incident
- **Overall confidence:** high | medium | low

## 1. Summary

<One paragraph: what happened, affected assets, disposition, confidence.>

## 2. Timeline (UTC)

| Time (UTC) | Event | Evidence ref |
|---|---|---|
| 2026-10-15T10:01:00Z | 87 sshd failures from 198[.]51[.]100[.]23 | evidence/auth.log#L4411 |
| 2026-10-15T10:07:00Z | successful password auth, user `deploy` | wazuh/alert_5715.json |

> Time zone of source hosts: <TZ>. Index timestamps are UTC.

## 3. Findings

| # | Finding | Basis | Confidence | Evidence |
|---|---|---|---|---|
| F1 | Brute force then success from 198[.]51[.]100[.]23 | observed | high | evidence/auth.log, wazuh/alert_5715.json |

*Basis = observed / inferred / assumed (Security Policy rule 9).*

## 4. Indicators (defanged)

| Type | Indicator | Disposition | Enrichment source |
|---|---|---|---|
| ipv4 | 198[.]51[.]100[.]23 | suspicious | <reputation source + UTC> |

## 5. MITRE ATT&CK

| Technique | ID | Supporting evidence |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | 87 failed auths |
| Valid Accounts | T1078 | success after brute force |

## 6. Recommendations & next action

- <action> — owner: <role> — approval required: none | human-approval | authorization-record

## 7. Handoff

See `handoff.yaml` (validated with `validate_handoff.py`).
