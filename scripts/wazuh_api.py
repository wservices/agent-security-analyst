#!/usr/bin/env python3
"""Read-only client for the Wazuh Server API and the Wazuh Indexer API.

Two DISTINCT APIs (they do not share auth or query model):

  * Server API  (default :55000) — JWT. Authenticate with HTTP basic to
    POST /security/user/authenticate?raw=true, then send Authorization: Bearer.
    Used for agents inventory, manager info, syscollector, sca, rootcheck, etc.
  * Indexer API (default :9200) — OpenSearch REST, HTTP basic per request.
    Query the wazuh-alerts-* indices with the _search DSL.

Safety:
  * READ-ONLY. Only GET (Server API) and _search (Indexer) are issued. No
    active-response, agent control, or rule changes (those require explicit
    authorization — Security Policy rules 2/4).
  * Credentials come from environment variables ONLY; never printed or logged.
  * The JWT is held in memory for the process; `--print-token` is intentionally
    NOT provided.
  * Self-signed clusters are common; TLS verification is ON by default and can
    be disabled per invocation with --insecure (documented, not default).

Env vars (names only — set in ~/.hermes/.env and forward via docker_forward_env):
  WAZUH_API_URL           e.g. https://wazuh.example.internal:55000
  WAZUH_API_USER
  WAZUH_API_PASSWORD
  WAZUH_INDEXER_URL       e.g. https://wazuh.example.internal:9200
  WAZUH_INDEXER_USER
  WAZUH_INDEXER_PASSWORD

Usage:
  wazuh_api.py agents [--status active] [--limit 100]
  wazuh_api.py server-get /manager/info
  wazuh_api.py alerts --query-file q.json [--index wazuh-alerts-*]
  wazuh_api.py alerts --rule-id 5710 --since 2026-10-15T00:00:00Z --limit 50
  wazuh_api.py alerts --agent-id 001 --min-level 7 --src-ip 198.51.100.23

Exit: 0 ok, 2 request/auth error, 3 usage/config error.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 30
UA = "agents-wazuh-client/0.1"


class WazuhError(Exception):
    pass


def _ssl_ctx(insecure: bool):
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None  # default verification


def _basic(user: str, pw: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def _request(url: str, method: str, headers: dict, body: bytes | None, insecure: bool):
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"User-Agent": UA, **headers})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ssl_ctx(insecure)) as r:  # noqa: S310
            raw = r.read().decode("utf-8")
            return json.loads(raw) if raw.strip().startswith(("{", "[")) else raw
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8")[:300]
        except Exception:  # noqa: BLE001
            pass
        raise WazuhError(f"HTTP {e.code} {method} {url.split('?')[0]} {detail}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise WazuhError(f"connection error to {url.split('?')[0]}: {e}") from e


# ---- Server API (JWT) -------------------------------------------------------

def _server_cfg():
    url = os.environ.get("WAZUH_API_URL")
    user = os.environ.get("WAZUH_API_USER")
    pw = os.environ.get("WAZUH_API_PASSWORD")
    if not (url and user and pw):
        raise WazuhError("set WAZUH_API_URL / WAZUH_API_USER / WAZUH_API_PASSWORD")
    return url.rstrip("/"), user, pw


def authenticate(insecure: bool) -> str:
    """Return a JWT (kept in-process). Never printed."""
    url, user, pw = _server_cfg()
    auth_url = f"{url}/security/user/authenticate?raw=true"
    token = _request(auth_url, "POST", {"Authorization": _basic(user, pw)}, None, insecure)
    if not isinstance(token, str) or not token.strip():
        raise WazuhError("authentication did not return a token")
    return token.strip()


def server_get(path: str, insecure: bool, params: dict | None = None):
    url, _, _ = _server_cfg()
    token = authenticate(insecure)
    full = f"{url}{path}"
    if params:
        full += "?" + urllib.parse.urlencode(params)
    return _request(full, "GET", {"Authorization": f"Bearer {token}"}, None, insecure)


def agents(insecure: bool, status: str | None, limit: int):
    params = {"limit": limit}
    if status:
        params["status"] = status
    return server_get("/agents", insecure, params)


# ---- Indexer API (OpenSearch _search) --------------------------------------

def _indexer_cfg():
    url = os.environ.get("WAZUH_INDEXER_URL")
    user = os.environ.get("WAZUH_INDEXER_USER")
    pw = os.environ.get("WAZUH_INDEXER_PASSWORD")
    if not (url and user and pw):
        raise WazuhError("set WAZUH_INDEXER_URL / WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD")
    return url.rstrip("/"), user, pw


def search_alerts(query: dict, index: str, insecure: bool):
    url, user, pw = _indexer_cfg()
    full = f"{url}/{index}/_search"
    body = json.dumps(query).encode()
    headers = {"Authorization": _basic(user, pw), "Content-Type": "application/json"}
    return _request(full, "POST", headers, body, insecure)


def build_alert_query(args) -> dict:
    """Compose an OpenSearch bool query from common filters."""
    must: list[dict] = []
    if args.rule_id:
        must.append({"term": {"rule.id": str(args.rule_id)}})
    if args.agent_id:
        must.append({"term": {"agent.id": str(args.agent_id)}})
    if args.min_level is not None:
        must.append({"range": {"rule.level": {"gte": args.min_level}}})
    if args.src_ip:
        # Wazuh commonly maps source IP to data.srcip
        must.append({"term": {"data.srcip": args.src_ip}})
    if args.since or args.until:
        rng: dict = {}
        if args.since:
            rng["gte"] = args.since
        if args.until:
            rng["lte"] = args.until
        must.append({"range": {"timestamp": rng}})
    query: dict = {
        "size": args.limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must or [{"match_all": {}}]}},
    }
    return query


def summarize_alerts(resp: dict) -> dict:
    hits = (resp or {}).get("hits", {})
    total = hits.get("total", {})
    total_n = total.get("value") if isinstance(total, dict) else total
    out = {"total": total_n, "returned": len(hits.get("hits", [])), "alerts": []}
    for h in hits.get("hits", []):
        s = h.get("_source", {})
        rule = s.get("rule", {})
        agent = s.get("agent", {})
        out["alerts"].append({
            "timestamp": s.get("timestamp"),
            "rule_id": rule.get("id"),
            "level": rule.get("level"),
            "description": rule.get("description"),
            "mitre": (rule.get("mitre") or {}).get("id"),
            "agent": agent.get("name") or agent.get("id"),
            "srcip": (s.get("data") or {}).get("srcip"),
        })
    return out


# ---- CLI --------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read-only Wazuh Server/Indexer client")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (self-signed clusters); documented, not default")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("agents", help="list agents (Server API)")
    pa.add_argument("--status", choices=["active", "disconnected", "never_connected", "pending"])
    pa.add_argument("--limit", type=int, default=100)

    pg = sub.add_parser("server-get", help="GET an arbitrary read-only Server API path")
    pg.add_argument("path")

    pl = sub.add_parser("alerts", help="search alerts (Indexer API)")
    pl.add_argument("--index", default="wazuh-alerts-*")
    pl.add_argument("--query-file", help="raw OpenSearch query JSON file (overrides filters)")
    pl.add_argument("--rule-id")
    pl.add_argument("--agent-id")
    pl.add_argument("--min-level", type=int)
    pl.add_argument("--src-ip")
    pl.add_argument("--since", help="ISO-8601, e.g. 2026-10-15T00:00:00Z")
    pl.add_argument("--until")
    pl.add_argument("--limit", type=int, default=50)
    pl.add_argument("--raw", action="store_true", help="print full response, not the summary")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "agents":
            print(json.dumps(agents(args.insecure, args.status, args.limit), indent=2))
            return 0
        if args.cmd == "server-get":
            if not args.path.startswith("/"):
                print("error: path must start with '/'", file=sys.stderr)
                return 3
            print(json.dumps(server_get(args.path, args.insecure), indent=2))
            return 0
        if args.cmd == "alerts":
            if args.query_file:
                with open(args.query_file, encoding="utf-8") as f:
                    query = json.load(f)
            else:
                query = build_alert_query(args)
            resp = search_alerts(query, args.index, args.insecure)
            out = resp if args.raw else summarize_alerts(resp)
            print(json.dumps(out, indent=2))
            return 0
    except WazuhError as e:
        print(f"wazuh error: {e}", file=sys.stderr)
        return 2
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
