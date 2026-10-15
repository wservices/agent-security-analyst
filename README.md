# security-analyst

Hermes cybersecurity agent: Tier-1/2 SOC analyst. Triages Wazuh alerts,
investigates Linux/network logs, extracts and enriches IOCs, maps to MITRE
ATT&CK, and produces evidence-backed investigation reports — escalating
confirmed incidents. Analysis and decision-support only; it never performs
response actions.

See `ROLE.md` for the full role definition, permitted/prohibited actions, and
escalation paths.

## Skills

| Skill | What it does |
|---|---|
| `wazuh-authentication` | Read-only auth to the Wazuh Server (JWT) + Indexer APIs |
| `wazuh-alert-search` | Filter alerts by agent/rule/IP/time (OpenSearch) |
| `wazuh-alert-triage` | Decide noise / benign / incident with evidence + ATT&CK |
| `linux-auth-log-analysis` | sshd brute-force and brute-force-then-success detection |
| `ioc-extraction` | Extract and defang IPs/domains/URLs/emails/hashes |
| `soc-investigation-reporting` | Structured report + validated `handoff.yaml` |

Additional SOC skills (web/firewall/DNS log analysis, phishing, correlation,
false-positive ID, escalation) are tracked as planned in
`agents/platform/IMPLEMENTATION.md`.

## Scripts (functional, tested)

| Script | Purpose |
|---|---|
| `scripts/wazuh_api.py` | Read-only Wazuh Server + Indexer client (no secrets logged) |
| `scripts/auth_log_analysis.py` | sshd auth-log brute-force analyzer |
| `scripts/ioc_extract.py` | IOC extraction + defanging |
| `scripts/validate_handoff.py` | Validate `handoff.yaml` against the platform schema |

## Tools

`tools/packages.txt` + `tools/install.sh` install the Kali tool layer
(`jq ripgrep tshark tcpdump nmap whois dnsutils openssl suricata yara`); `zeek`
is optional (not reliably in Kali apt). Live capture needs `--cap-add NET_RAW`
(never `--privileged`). See `tools/README.md`.

## Install into Hermes (as a profile)

This repo is a **Hermes profile distribution** (`distribution.yaml` + `SOUL.md` +
`skills/`). Install it as its own agent profile:

```bash
export GITLAB_HOST=gitlab.wservices.ch
hermes profile install "git@$GITLAB_HOST:agents/cybersecurity/security-analyst.git"
hermes -p security-analyst chat              # run the analyst
hermes profile update security-analyst       # re-pull later; keeps your .env/memory
```

On install, Hermes generates a `.env.EXAMPLE` from `distribution.yaml`'s
`env_requires` (Wazuh/NVD vars). Copy it to `.env`, fill in your values, and
forward the names into the Kali sandbox via `docker_forward_env`. `config.yaml`
is **not** overwritten (your model/provider is preserved).

Shared skills (`cve-research`, `security-tooling` under `skills/security/…`) are
pinned and installed separately — see `agents/platform/docs/GITLAB-ARCHITECTURE.md`
and `HERMES-INTEGRATION.md` §6 for the profile + shared-skill mechanism.

## Tests

```bash
python3 -m pytest tests -q     # 23 tests: Wazuh client, IOC, auth-log, handoff — all mocked, no network
```

## Example

`examples/ssh-bruteforce-investigation.md` walks the full loop end to end with a
synthetic log and expected output.

## Security

Bound by `agents/platform/policies/SECURITY-POLICY.md`: read-only by default, no
response actions, evidence preserved, secrets never committed/logged, untrusted
log content treated as data (never instructions).

## License

MIT.
