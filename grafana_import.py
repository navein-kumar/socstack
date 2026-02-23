#!/usr/bin/env python3
"""
Fix Grafana datasources and import Wazuh dashboards 21565 + 23072
"""
import json, urllib.request, urllib.error, base64, time

GF = "http://localhost:3000"
USER = "admin"
PASS = "SocGrafana@2025"
OS_UID = "PCE9BE10AEFA73E90"   # Wazuh-OpenSearch datasource uid
ES_UID = "cfdj6iviw19tsa"      # elasticsearch datasource uid

token = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
HDR  = {"Content-Type": "application/json", "Authorization": f"Basic {token}"}

def api(method, path, data=None):
    url = GF + path
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=HDR, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "msg": e.read().decode()[:300]}

# ── Step 1: Fix OpenSearch datasource — correct index ─────────────────────────
print("=== Step 1: Fix Wazuh-OpenSearch datasource index ===")
result = api("PUT", "/api/datasources/1", {
    "id": 1,
    "uid": OS_UID,
    "orgId": 1,
    "name": "Wazuh-OpenSearch",
    "type": "grafana-opensearch-datasource",
    "access": "proxy",
    "url": "https://socstack-wazuh-indexer:9200",
    "basicAuth": True,
    "basicAuthUser": "admin",
    "secureJsonData": {"basicAuthPassword": "SecretPassword"},
    "isDefault": True,
    "jsonData": {
        "database": "wazuh-alerts-4.x-*",
        "flavor": "opensearch",
        "version": "2.19.1",
        "timeField": "@timestamp",
        "tlsSkipVerify": True,
        "maxConcurrentShardRequests": 5,
        "logMessageField": "rule.description",
        "logLevelField": "rule.level"
    }
})
print("  OpenSearch DS:", result.get("message", result))

# Also fix elasticsearch DS index
result2 = api("PUT", "/api/datasources/4", {
    "id": 4,
    "uid": ES_UID,
    "orgId": 1,
    "name": "elasticsearch",
    "type": "elasticsearch",
    "access": "proxy",
    "url": "https://socstack-wazuh-indexer:9200",
    "basicAuth": True,
    "basicAuthUser": "admin",
    "secureJsonData": {"basicAuthPassword": "SecretPassword"},
    "isDefault": False,
    "jsonData": {
        "esVersion": "7.10.0",
        "index": "wazuh-alerts-4.x-*",
        "timeField": "@timestamp",
        "tlsSkipVerify": True,
        "maxConcurrentShardRequests": 5,
        "logMessageField": "rule.description",
        "logLevelField": "rule.level",
        "interval": "Daily"
    }
})
print("  Elasticsearch DS:", result2.get("message", result2))

# ── Step 2: Health checks ──────────────────────────────────────────────────────
print("\n=== Step 2: Health checks ===")
h1 = api("GET", "/api/datasources/1/health")
print("  OpenSearch:", h1.get("status","?"), "|", h1.get("message","?"))
h2 = api("GET", "/api/datasources/4/health")
print("  Elasticsearch:", h2.get("status","?"), "|", h2.get("message","?"))

# ── Step 3: Download + patch + import dashboard 21565 ─────────────────────────
print("\n=== Step 3: Import dashboard 21565 (SIEM XDR Wazuh 4.8.0) ===")
url = "https://grafana.com/api/dashboards/21565/revisions/latest/download"
req = urllib.request.Request(url)
with urllib.request.urlopen(req) as r:
    dash_json = json.loads(r.read())

# Remap all datasource inputs to our OpenSearch DS
def remap_datasources(obj, os_uid, es_uid):
    """Walk the dashboard JSON and remap all datasource references"""
    if isinstance(obj, dict):
        # Fix datasource references inside panels/targets
        if "datasource" in obj:
            ds = obj["datasource"]
            if isinstance(ds, dict):
                t = ds.get("type","")
                if t in ("grafana-opensearch-datasource", "elasticsearch", "opensearch"):
                    ds["uid"] = os_uid
                    ds["type"] = "grafana-opensearch-datasource"
        # Fix __inputs style uid references
        for k, v in obj.items():
            obj[k] = remap_datasources(v, os_uid, es_uid)
    elif isinstance(obj, list):
        return [remap_datasources(i, os_uid, es_uid) for i in obj]
    return obj

dash_json = remap_datasources(dash_json, OS_UID, ES_UID)
dash_json.pop("id", None)

# Build inputs mapping - map ALL input types to our OpenSearch DS
inputs = []
for inp in dash_json.get("__inputs", []):
    inputs.append({
        "name": inp.get("name"),
        "type": "datasource",
        "pluginId": "grafana-opensearch-datasource",
        "value": "Wazuh-OpenSearch"
    })

result = api("POST", "/api/dashboards/import", {
    "dashboard": dash_json,
    "overwrite": True,
    "inputs": inputs,
    "folderId": 0
})
print("  Status:", result.get("status", result.get("error","?")))
print("  URL:", "https://grafana.codesec.in" + result.get("importedUrl",""))

# ── Step 4: Download + patch + import dashboard 23072 ─────────────────────────
print("\n=== Step 4: Import dashboard 23072 (EDR FIM) ===")
url2 = "https://grafana.com/api/dashboards/23072/revisions/latest/download"
req2 = urllib.request.Request(url2)
with urllib.request.urlopen(req2) as r:
    dash_json2 = json.loads(r.read())

dash_json2 = remap_datasources(dash_json2, OS_UID, ES_UID)
dash_json2.pop("id", None)

inputs2 = []
for inp in dash_json2.get("__inputs", []):
    inputs2.append({
        "name": inp.get("name"),
        "type": "datasource",
        "pluginId": "grafana-opensearch-datasource",
        "value": "Wazuh-OpenSearch"
    })

result2 = api("POST", "/api/dashboards/import", {
    "dashboard": dash_json2,
    "overwrite": True,
    "inputs": inputs2,
    "folderId": 0
})
print("  Status:", result2.get("status", result2.get("error","?")))
print("  URL:", "https://grafana.codesec.in" + result2.get("importedUrl",""))

# ── Step 5: Delete old broken custom dashboard, rebuild with OpenSearch ────────
print("\n=== Step 5: Rebuild Security Events dashboard using OpenSearch DS ===")

dashboard = {
    "uid": "wazuh-security-events",
    "title": "Wazuh - Security Events",
    "tags": ["wazuh", "security", "siem"],
    "timezone": "browser",
    "refresh": "1m",
    "time": {"from": "now-24h", "to": "now"},
    "schemaVersion": 38,
    "panels": [
        # Stat: Total Events
        {
            "id": 1, "type": "stat", "title": "Total Events",
            "gridPos": {"x": 0, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"fixedColor": "blue", "mode": "fixed"}, "thresholds": {"steps": [{"color": "blue", "value": None}]}}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene",
                "query": "*",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "1d", "min_doc_count": "0"}}],
                "timeField": "@timestamp"
            }]
        },
        # Stat: Auth Failures
        {
            "id": 2, "type": "stat", "title": "Auth Failures",
            "gridPos": {"x": 4, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"fixedColor": "red", "mode": "fixed"}}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene",
                "query": "rule.groups:authentication_failed",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "1d", "min_doc_count": "0"}}],
                "timeField": "@timestamp"
            }]
        },
        # Stat: High Severity
        {
            "id": 3, "type": "stat", "title": "High Severity (>=10)",
            "gridPos": {"x": 8, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"fixedColor": "orange", "mode": "fixed"}}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene",
                "query": "rule.level:>=10",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "1d", "min_doc_count": "0"}}],
                "timeField": "@timestamp"
            }]
        },
        # Stat: SSH Brute Force
        {
            "id": 4, "type": "stat", "title": "SSH Brute Force",
            "gridPos": {"x": 12, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"fixedColor": "dark-red", "mode": "fixed"}}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene",
                "query": "rule.groups:sshd AND rule.groups:authentication_failed",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "1d", "min_doc_count": "0"}}],
                "timeField": "@timestamp"
            }]
        },
        # Stat: Windows Events
        {
            "id": 5, "type": "stat", "title": "Windows Events",
            "gridPos": {"x": 16, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"fixedColor": "purple", "mode": "fixed"}}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene",
                "query": "rule.groups:windows",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "1d", "min_doc_count": "0"}}],
                "timeField": "@timestamp"
            }]
        },
        # Stat: Syslog Events
        {
            "id": 6, "type": "stat", "title": "Syslog Events",
            "gridPos": {"x": 20, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"fixedColor": "green", "mode": "fixed"}}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene",
                "query": "rule.groups:syslog",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "1d", "min_doc_count": "0"}}],
                "timeField": "@timestamp"
            }]
        },

        # Timeseries: Events over time
        {
            "id": 10, "type": "timeseries", "title": "Security Events Over Time",
            "gridPos": {"x": 0, "y": 4, "w": 24, "h": 8},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 8}}},
            "options": {"tooltip": {"mode": "multi"}},
            "targets": [
                {
                    "refId": "A", "alias": "All Events",
                    "queryType": "lucene", "query": "*",
                    "metrics": [{"id": "1", "type": "count"}],
                    "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "auto", "min_doc_count": "0"}}],
                    "timeField": "@timestamp"
                },
                {
                    "refId": "B", "alias": "Auth Failures",
                    "queryType": "lucene", "query": "rule.groups:authentication_failed",
                    "metrics": [{"id": "1", "type": "count"}],
                    "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "auto", "min_doc_count": "0"}}],
                    "timeField": "@timestamp"
                },
                {
                    "refId": "C", "alias": "High Severity (>=10)",
                    "queryType": "lucene", "query": "rule.level:>=10",
                    "metrics": [{"id": "1", "type": "count"}],
                    "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp", "settings": {"interval": "auto", "min_doc_count": "0"}}],
                    "timeField": "@timestamp"
                }
            ]
        },

        # Bar: Top Agents
        {
            "id": 20, "type": "barchart", "title": "Top 10 Agents by Events",
            "gridPos": {"x": 0, "y": 12, "w": 12, "h": 8},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"xTickLabelRotation": -45, "barWidth": 0.7, "legend": {"displayMode": "hidden"}},
            "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene", "query": "*",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "terms", "field": "agent.name", "settings": {"size": "10", "order": "desc", "orderBy": "1"}}],
                "timeField": "@timestamp"
            }]
        },

        # Bar: Top Rules
        {
            "id": 21, "type": "barchart", "title": "Top 10 Rules Triggered",
            "gridPos": {"x": 12, "y": 12, "w": 12, "h": 8},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"xTickLabelRotation": -45, "barWidth": 0.7, "legend": {"displayMode": "hidden"}},
            "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene", "query": "*",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "terms", "field": "rule.description", "settings": {"size": "10", "order": "desc", "orderBy": "1"}}],
                "timeField": "@timestamp"
            }]
        },

        # Pie: Severity
        {
            "id": 30, "type": "piechart", "title": "Events by Rule Level",
            "gridPos": {"x": 0, "y": 20, "w": 8, "h": 8},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"pieType": "donut", "legend": {"placement": "right", "displayMode": "table", "values": ["value", "percent"]}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene", "query": "*",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "terms", "field": "rule.level", "settings": {"size": "15", "order": "desc", "orderBy": "1"}}],
                "timeField": "@timestamp"
            }]
        },

        # Pie: Rule Groups
        {
            "id": 31, "type": "piechart", "title": "Top Rule Groups",
            "gridPos": {"x": 8, "y": 20, "w": 8, "h": 8},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"pieType": "donut", "legend": {"placement": "right", "displayMode": "table", "values": ["value", "percent"]}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene", "query": "*",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "terms", "field": "rule.groups", "settings": {"size": "10", "order": "desc", "orderBy": "1"}}],
                "timeField": "@timestamp"
            }]
        },

        # Bar: Top Attack IPs
        {
            "id": 32, "type": "barchart", "title": "Top 10 Attack Source IPs",
            "gridPos": {"x": 16, "y": 20, "w": 8, "h": 8},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"xTickLabelRotation": -45, "legend": {"displayMode": "hidden"}},
            "fieldConfig": {"defaults": {"color": {"fixedColor": "red", "mode": "fixed"}}},
            "targets": [{
                "refId": "A",
                "queryType": "lucene",
                "query": "rule.groups:authentication_failed AND data.srcip:*",
                "metrics": [{"id": "1", "type": "count"}],
                "bucketAggs": [{"id": "2", "type": "terms", "field": "data.srcip", "settings": {"size": "10", "order": "desc", "orderBy": "1"}}],
                "timeField": "@timestamp"
            }]
        },

        # Table: Recent events
        {
            "id": 40, "type": "table", "title": "Recent Security Events (Latest 100)",
            "gridPos": {"x": 0, "y": 28, "w": 24, "h": 10},
            "datasource": {"type": "grafana-opensearch-datasource", "uid": OS_UID},
            "options": {"sortBy": [{"displayName": "Time", "desc": True}]},
            "fieldConfig": {
                "defaults": {},
                "overrides": [
                    {"matcher": {"id": "byName", "options": "rule.level"}, "properties": [
                        {"id": "custom.width", "value": 90},
                        {"id": "displayName", "value": "Level"},
                        {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                            {"color": "green", "value": None},
                            {"color": "yellow", "value": 5},
                            {"color": "orange", "value": 10},
                            {"color": "red", "value": 12}
                        ]}},
                        {"id": "custom.displayMode", "value": "color-background"}
                    ]},
                    {"matcher": {"id": "byName", "options": "agent.name"}, "properties": [{"id": "custom.width", "value": 160}, {"id": "displayName", "value": "Agent"}]},
                    {"matcher": {"id": "byName", "options": "rule.description"}, "properties": [{"id": "custom.width", "value": 420}, {"id": "displayName", "value": "Rule"}]},
                    {"matcher": {"id": "byName", "options": "data.srcip"}, "properties": [{"id": "custom.width", "value": 140}, {"id": "displayName", "value": "Src IP"}]},
                    {"matcher": {"id": "byName", "options": "rule.groups"}, "properties": [{"id": "custom.width", "value": 200}, {"id": "displayName", "value": "Groups"}]}
                ]
            },
            "targets": [{
                "refId": "A",
                "queryType": "lucene", "query": "*",
                "metrics": [{"id": "1", "type": "raw_data", "settings": {"size": "100"}}],
                "bucketAggs": [],
                "timeField": "@timestamp"
            }]
        }
    ]
}

result3 = api("POST", "/api/dashboards/db", {
    "dashboard": dashboard,
    "overwrite": True,
    "folderId": 0
})
print("  Status:", result3.get("status", result3.get("error","?")))
print("  URL:", "https://grafana.codesec.in" + result3.get("url", ""))

# ── Step 6: List all dashboards ────────────────────────────────────────────────
print("\n=== All dashboards now available ===")
all_dash = api("GET", "/api/search?type=dash-db")
for d in all_dash:
    print(f"  - {d['title']}")
    print(f"    https://grafana.codesec.in{d['url']}")
