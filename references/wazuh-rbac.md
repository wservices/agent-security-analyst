# Wazuh read-only access for the Security Analyst

The analyst uses a **read-only** account on both APIs. Configure least-privilege
RBAC; do not reuse the admin `wazuh`/`wazuh-wui` accounts.

## Server API (RBAC)

Create a role whose policies allow only read actions and assign it to a
dedicated analyst user. Read-only actions include (non-exhaustive):

- `agent:read`, `group:read`
- `manager:read`, `cluster:read`
- `syscheck:read`, `rootcheck:read`, `sca:read`
- `syscollector:read`, `vulnerability:read`

Explicitly do NOT grant: `active-response:command`, `agent:restart`,
`agent:delete`, `manager:restart`, `*:update`, `*:create`, `*:delete`.

Manage via the Server API `/security/*` endpoints or the Wazuh dashboard
(Security → Roles/Policies/Users). See the Wazuh RBAC docs for the exact policy
JSON for your version.

## Indexer (OpenSearch) access

Create an OpenSearch role granting read (`read`, `search`) on the
`wazuh-alerts-*` (and `wazuh-archives-*` if used) index patterns only, mapped to
a dedicated analyst user. No write/manage/cluster-admin permissions.

## Credentials

Store the analyst credentials outside the repo: in `~/.hermes/.env`, forwarded
into the sandbox via `docker_forward_env`. Never commit them. The client script
reads them from env and never prints them.
