---
name: wazuh-authentication
description: Authenticate to the Wazuh Server and Indexer APIs.
version: 0.1.0
author: Pascal (pascal), Hermes Agent
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [wazuh, api, authentication, jwt, indexer]
    related_skills: [wazuh-alert-search, wazuh-alert-triage]
---

# Wazuh Authentication Skill

Establish read-only authenticated access to the two distinct Wazuh APIs: the
Server API (JWT, port 55000) and the Indexer API (OpenSearch basic auth, port
9200). It never prints tokens or credentials and defaults to read-only access.

## When to Use

- Before any Wazuh query skill (alert search, agent inventory, SCA, syscheck).
- Verifying connectivity/credentials to a new Wazuh deployment.
- **Don't use for:** active response, agent control, or rule changes — those are
  out of scope for the Security Analyst and require explicit authorization
  (Security Policy rules 2/4).

## Prerequisites

- Env vars (names only; set in `~/.hermes/.env`, forward via `docker_forward_env`):
  - Server API: `WAZUH_API_URL` (`https://host:55000`), `WAZUH_API_USER`,
    `WAZUH_API_PASSWORD`
  - Indexer API: `WAZUH_INDEXER_URL` (`https://host:9200`),
    `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`
- The account must be a **read-only** Wazuh RBAC role (see `references/wazuh-rbac.md`).
- `python3` (stdlib only). Network egress to ports 55000 and 9200.
- Self-signed clusters: pass `--insecure` (documented; not the default).

## How to Run

`terminal(command="python3 scripts/wazuh_api.py server-get /manager/info", timeout=30)`

The Server API flow (handled by the script): `POST /security/user/authenticate?raw=true`
with HTTP basic auth returns a raw JWT (default TTL 900 s); subsequent calls send
`Authorization: Bearer <jwt>`. The Indexer API uses HTTP basic auth per request.

## Quick Reference

```
python3 scripts/wazuh_api.py server-get /manager/info     # proves Server API auth
python3 scripts/wazuh_api.py agents --limit 1             # proves Server API read
python3 scripts/wazuh_api.py alerts --limit 1            # proves Indexer API auth+read
```

## Procedure

1. **Confirm env vars are present** (names only; never echo values). Completion:
   the three Server vars and/or three Indexer vars are set for what you need.
2. **Server API check.** Run `server-get /manager/info`. Completion: JSON with
   the manager version returns (HTTP 200); a 401 means bad creds, a connection
   error means wrong URL/port or TLS.
3. **Indexer API check.** Run `alerts --limit 1`. Completion: a summary with a
   `total` count returns. A 401 is Indexer creds; an index-not-found error means
   the `wazuh-alerts-*` pattern differs on this cluster.
4. **TLS posture.** If the cluster uses the default self-signed cert, re-run with
   `--insecure` and record that verification was skipped in the case notes.
   Completion: both checks succeed with the chosen TLS posture documented.

## Pitfalls

- **Two APIs, two credentials.** Server (55000/JWT) ≠ Indexer (9200/basic). A
  working Server check does not imply Indexer access.
- **Token TTL.** The JWT expires (~15 min default); the script re-authenticates
  per invocation, so long gaps between calls are fine.
- **Never log secrets.** The script holds the JWT in memory only and offers no
  `--print-token`. Do not add one.
- **Read-only RBAC.** If a call unexpectedly needs write scope, stop — do not
  escalate the account to make it work (rule 13).

## Verification

- `server-get /manager/info` returns a version string.
- `alerts --limit 1` returns a JSON object containing `total`.
- No credential or token value appears anywhere in stdout/stderr or logs.
