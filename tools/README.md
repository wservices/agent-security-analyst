# security-analyst tools

| Tool | Purpose | Source | Risk |
|---|---|---|---|
| jq | parse/filter JSON (Wazuh, API output) | base image / apt | low |
| ripgrep (`rg`) | fast log search | base / apt | low |
| tshark | CLI packet analysis | base / apt | capture needs NET_RAW |
| tcpdump | packet capture/inspection | base / apt | capture needs NET_RAW |
| nmap | host/service discovery (authorized only) | base / apt | scanning = authorization-gated |
| whois | registration/ownership lookup | base / apt | low (external query) |
| dig (dnsutils) | DNS resolution/history | base / apt | low |
| openssl | TLS/cert inspection | base / apt | low |
| suricata | IDS alerts, offline rule testing | apt | low (offline); live = NET_RAW |
| yara | match byte/string patterns in files | apt | low |
| zeek (optional) | network metadata analysis | upstream OBS repo | not in Kali apt |

## Install

```bash
# with the shared installer (preferred)
SECURITY_TOOLING_DIR=/path/to/security-tooling bash tools/install.sh
# standalone fallback (apt only)
bash tools/install.sh
```

## Verify

```bash
# via the shared skill's verifier
bash /path/to/security-tooling/skills/security-tooling/scripts/verify_tools.sh --from-file tools/verify.txt
```

## Capabilities

Analysis is unprivileged. **Live** packet capture (`tcpdump`, `tshark`,
`nmap -sS`, live Suricata) needs `--cap-add NET_RAW` via `docker_extra_args` —
never `--privileged` (Security Policy §4). Authorized scanning only.
