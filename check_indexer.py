"""
Quick diagnostic — run this to verify connectivity and see what's in your indexer.
Usage: uv run src/check_indexer.py
"""
import os, json, requests, urllib3
from dotenv import load_dotenv

load_dotenv()

host = os.getenv("INDEXER_HOST", "localhost")
port = os.getenv("INDEXER_PORT", "9200")
user = os.getenv("INDEXER_USER", "admin")
pwd  = os.getenv("INDEXER_PASS", "admin")
ssl  = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

if host.startswith("http"):
    base = host.rstrip("/")
else:
    base = f"https://{host}:{port}"

urllib3.disable_warnings()
s = requests.Session()
s.auth = (user, pwd)
s.verify = ssl

print(f"\n=== Connecting to {base} ===\n")

# 1. Cluster health
r = s.get(f"{base}/_cluster/health", timeout=10)
health = r.json()
print(f"Cluster health : {health.get('status','?')}  nodes={health.get('number_of_nodes','?')}")

# 2. List wazuh-* indices (text/plain format avoids the JSON parse issue)
r = s.get(f"{base}/_cat/indices/wazuh-*?format=json&s=index", timeout=10)
indices = r.json()
# _cat returns either a list of dicts or a single string on error
if isinstance(indices, list) and indices and isinstance(indices[0], dict):
    print(f"\nWazuh indices ({len(indices)} found):")
    for idx in indices:
        print(f"  {idx.get('index','?'):60s}  docs={idx.get('docs.count','?'):>8}  size={idx.get('store.size','?')}")
else:
    print(f"\nIndex list raw response: {indices}")

# 3. Sample latest alert — no time filter, just match_all
print("\n=== Latest doc in wazuh-alerts-* (no time filter) ===")
body = {"size": 1, "query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "desc"}}]}
r = s.post(f"{base}/wazuh-alerts-*/_search", json=body, timeout=10)
if r.ok:
    data  = r.json()
    total = data.get("hits", {}).get("total", {}).get("value", 0)
    hits  = data.get("hits", {}).get("hits", [])
    print(f"  Total docs (no filter): {total}")
    if hits:
        src = hits[0]["_source"]
        print(f"  @timestamp   : {src.get('@timestamp', 'MISSING')}")
        print(f"  timestamp    : {src.get('timestamp',  'MISSING')}")
        print(f"  rule.level   : {src.get('rule', {}).get('level', 'MISSING')}")
        print(f"  agent.name   : {src.get('agent', {}).get('name', 'MISSING')}")
        print(f"  rule.desc    : {src.get('rule', {}).get('description', 'MISSING')}")
else:
    print(f"  Error {r.status_code}: {r.text[:300]}")

# 4. Sample with last 24h time filter
print("\n=== Latest doc in wazuh-alerts-* (last 24h, @timestamp) ===")
body24 = {
    "size": 1,
    "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}]}},
    "sort": [{"@timestamp": {"order": "desc"}}],
}
r = s.post(f"{base}/wazuh-alerts-*/_search", json=body24, timeout=10)
if r.ok:
    total = r.json().get("hits", {}).get("total", {}).get("value", 0)
    print(f"  Total docs last 24h: {total}")
else:
    print(f"  Error {r.status_code}: {r.text[:300]}")

# 5. Count by level (all time)
print("\n=== Alert count by rule.level (all time) ===")
agg_body = {
    "size": 0,
    "aggs": {"by_level": {"terms": {"field": "rule.level", "size": 16, "order": {"_key": "desc"}}}},
}
r = s.post(f"{base}/wazuh-alerts-*/_search", json=agg_body, timeout=10)
if r.ok:
    buckets = r.json().get("aggregations", {}).get("by_level", {}).get("buckets", [])
    if buckets:
        for b in buckets:
            print(f"  level {b['key']:>2} : {b['doc_count']} alerts")
    else:
        print("  No aggregation results (index may be empty)")
else:
    print(f"  Error {r.status_code}: {r.text[:300]}")