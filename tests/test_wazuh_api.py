"""Tests for wazuh_api.py — mocked HTTP, no live cluster, no secrets."""
import importlib.util
import sys
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("wazuh_api", ROOT / "scripts" / "wazuh_api.py")
wz = importlib.util.module_from_spec(spec)
sys.modules["wazuh_api"] = wz
spec.loader.exec_module(wz)

ENV = {
    "WAZUH_API_URL": "https://wazuh.test:55000",
    "WAZUH_API_USER": "ro-user",
    "WAZUH_API_PASSWORD": "ignored-in-tests",
    "WAZUH_INDEXER_URL": "https://wazuh.test:9200",
    "WAZUH_INDEXER_USER": "ro-user",
    "WAZUH_INDEXER_PASSWORD": "ignored-in-tests",
}

ALERTS_RESP = {
    "hits": {
        "total": {"value": 2},
        "hits": [
            {"_source": {
                "timestamp": "2026-10-15T10:01:00Z",
                "rule": {"id": "5710", "level": 5, "description": "sshd: invalid user",
                         "mitre": {"id": ["T1110.001"]}},
                "agent": {"id": "001", "name": "web01"},
                "data": {"srcip": "198.51.100.23"},
            }},
            {"_source": {
                "timestamp": "2026-10-15T10:02:00Z",
                "rule": {"id": "5715", "level": 5, "description": "sshd: authentication success"},
                "agent": {"id": "001", "name": "web01"},
                "data": {"srcip": "198.51.100.23"},
            }},
        ],
    }
}


def test_server_cfg_requires_env():
    with mock.patch.dict(wz.os.environ, {}, clear=True):
        with pytest.raises(wz.WazuhError):
            wz._server_cfg()


def test_authenticate_returns_token_and_never_prints(capsys):
    with mock.patch.dict(wz.os.environ, ENV, clear=True), \
         mock.patch.object(wz, "_request", return_value="JWT.„raw“.token") as req:
        tok = wz.authenticate(insecure=True)
    assert tok == "JWT.„raw“.token"
    # authenticate hits the raw=true endpoint with basic auth, POST:
    args, kwargs = req.call_args
    assert args[0].endswith("/security/user/authenticate?raw=true")
    assert args[1] == "POST"
    assert args[2]["Authorization"].startswith("Basic ")
    # nothing leaked to stdout
    assert capsys.readouterr().out == ""


def test_build_alert_query_filters():
    class A:
        rule_id = "5710"; agent_id = "001"; min_level = 7
        src_ip = "198.51.100.23"; since = "2026-10-15T00:00:00Z"; until = None; limit = 25
    q = wz.build_alert_query(A())
    must = q["query"]["bool"]["must"]
    assert {"term": {"rule.id": "5710"}} in must
    assert {"term": {"agent.id": "001"}} in must
    assert {"range": {"rule.level": {"gte": 7}}} in must
    assert {"term": {"data.srcip": "198.51.100.23"}} in must
    assert q["size"] == 25
    assert q["sort"] == [{"timestamp": {"order": "desc"}}]


def test_build_alert_query_defaults_match_all():
    class A:
        rule_id = None; agent_id = None; min_level = None
        src_ip = None; since = None; until = None; limit = 50
    q = wz.build_alert_query(A())
    assert q["query"]["bool"]["must"] == [{"match_all": {}}]


def test_summarize_alerts():
    out = wz.summarize_alerts(ALERTS_RESP)
    assert out["total"] == 2
    assert out["returned"] == 2
    first = out["alerts"][0]
    assert first["rule_id"] == "5710"
    assert first["mitre"] == ["T1110.001"]
    assert first["agent"] == "web01"
    assert first["srcip"] == "198.51.100.23"


def test_search_alerts_posts_to_indexer():
    with mock.patch.dict(wz.os.environ, ENV, clear=True), \
         mock.patch.object(wz, "_request", return_value=ALERTS_RESP) as req:
        resp = wz.search_alerts({"query": {"match_all": {}}}, "wazuh-alerts-*", insecure=True)
    assert resp["hits"]["total"]["value"] == 2
    url, method = req.call_args[0][0], req.call_args[0][1]
    assert url.endswith("/wazuh-alerts-*/_search")
    assert method == "POST"
