# OpenSearch query recipes for wazuh-alerts-*

Pass these to `scripts/wazuh_api.py alerts --query-file q.json --raw`.

## Brute force from one source, last 24h

```json
{
  "size": 100,
  "sort": [{"timestamp": {"order": "desc"}}],
  "query": {"bool": {"must": [
    {"term": {"rule.groups": "authentication_failed"}},
    {"term": {"data.srcip": "198.51.100.23"}},
    {"range": {"timestamp": {"gte": "now-24h"}}}
  ]}}
}
```

## Successful auth after failures (correlation seed)

```json
{
  "size": 50,
  "sort": [{"timestamp": {"order": "asc"}}],
  "query": {"bool": {"must": [
    {"terms": {"rule.id": ["5715", "5501"]}},
    {"range": {"timestamp": {"gte": "now-24h"}}}
  ]}}
}
```

## Aggregate top source IPs by alert count

```json
{
  "size": 0,
  "query": {"range": {"timestamp": {"gte": "now-7d"}}},
  "aggs": {"top_src": {"terms": {"field": "data.srcip", "size": 20}}}
}
```

## Field notes

- Source IP: usually `data.srcip` (keyword). Some decoders use other fields —
  inspect a raw hit if a filter returns nothing.
- Severity: `rule.level` (integer). MITRE: `rule.mitre.id` (array).
- Time: `timestamp` (UTC). OpenSearch date-math (`now-24h`) works in ranges.
- Rule grouping: `rule.groups` (keyword array) is often more stable than a
  single `rule.id` across Wazuh versions.
