# Worked example: SSH brute-force-then-success investigation

End-to-end run of the security-analyst loop against a synthetic `auth.log`.

## 0. Setup (synthetic evidence)

```bash
mkdir -p cases/CASE-2026-0142/evidence && cd cases/CASE-2026-0142
# (synthetic log generated for the example; see tests for the same shape)
printf '%s\n' \
  "Oct 15 10:01:00 web01 sshd[4411]: Failed password for invalid user admin from 198.51.100.23 port 51234 ssh2" \
  "Oct 15 10:01:04 web01 sshd[4412]: Failed password for root from 198.51.100.23 port 51238 ssh2" \
  "Oct 15 10:07:00 web01 sshd[4420]: Accepted password for deploy from 198.51.100.23 port 51260 ssh2" \
  > evidence/auth.log
sha256sum evidence/auth.log | tee evidence/auth.log.sha256
```

## 1. Analyze auth log

```bash
python3 scripts/auth_log_analysis.py evidence/auth.log --threshold 2 --json
```

Expected (abridged):

```json
{
  "total_sources_flagged": 1,
  "findings": [
    {
      "src_ip": "198.51.100.23",
      "failures": 2,
      "successful_users": ["deploy"],
      "success_after_bruteforce_user": "deploy",
      "flags": ["brute-force-then-success"],
      "severity": "critical",
      "attack_mapping": ["T1110.001", "T1078"]
    }
  ]
}
```

## 2. Extract + defang indicators

```bash
python3 scripts/ioc_extract.py --json --public-only evidence/auth.log
```

Expected: `"ipv4": ["198[.]51[.]100[.]23"]` (public, defanged).

## 3. Correlate in Wazuh (if alerts exist)

```bash
python3 scripts/wazuh_api.py alerts --src-ip 198.51.100.23 --since 2026-10-15T09:00:00Z --limit 50
```

## 4. Disposition

`incident` — brute force from `198[.]51[.]100[.]23` followed by a successful
`deploy` login. Confidence **high** (observed in auth.log; corroborated by rule
5715). Next action: escalate to Incident Responder; confirm whether `deploy`
login was expected.

## 5. Handoff

See `examples/handoff.yaml`; validate with:

```bash
python3 scripts/validate_handoff.py examples/handoff.yaml   # -> "handoff OK"
```
