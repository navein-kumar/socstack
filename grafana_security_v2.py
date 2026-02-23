#!/usr/bin/env python3
"""
Grafana 12 compatible Wazuh Security Events dashboard
Uses elasticsearch datasource with correct query format for Grafana 12
"""
import json, urllib.request, urllib.error, base64

GF   = "http://localhost:3000"
USER = "admin"
PASS = "SocGrafana@2025"
# Use elasticsearch DS - proxy confirmed working (10605 docs)
DS   = {"type": "elasticsearch", "uid": "cfdj6iviw19tsa"}

token = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
HDR   = {"Content-Type": "application/json", "Authorization": f"Basic {token}"}

def api(method, path, data=None):
    body = json.dumps(data).encode() if data else None
    req  = urllib.request.Request(GF + path, data=body, headers=HDR, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read().decode()[:400]}

def stat_panel(pid, title, query, color, x, y, w=4, h=4):
    """Grafana 12 stat panel - uses date_histogram with sum reducer"""
    return {
        "id": pid, "type": "stat", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS,
        "options": {
            "reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
            "colorMode": "background",
            "graphMode": "none",
            "textMode": "auto",
            "orientation": "auto"
        },
        "fieldConfig": {
            "defaults": {
                "color": {"fixedColor": color, "mode": "fixed"},
                "mappings": [],
                "thresholds": {"mode": "absolute", "steps": [{"color": color, "value": None}]},
                "unit": "short"
            },
            "overrides": []
        },
        "targets": [{
            "refId": "A",
            "query": query,
            "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": [{
                "id": "2",
                "type": "date_histogram",
                "field": "@timestamp",
                "settings": {"interval": "1d", "min_doc_count": "0", "trimEdges": "0"}
            }],
            "timeField": "@timestamp",
            "datasource": DS
        }]
    }

def timeseries_panel(pid, title, targets, x, y, w=24, h=8):
    return {
        "id": pid, "type": "timeseries", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS,
        "fieldConfig": {
            "defaults": {
                "custom": {"lineWidth": 2, "fillOpacity": 8, "gradientMode": "none", "showPoints": "never"},
                "color": {"mode": "palette-classic"}
            },
            "overrides": []
        },
        "options": {"tooltip": {"mode": "multi", "sort": "none"}, "legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": targets
    }

def ts_target(ref, alias, query):
    return {
        "refId": ref, "alias": alias, "query": query,
        "metrics": [{"id": "1", "type": "count"}],
        "bucketAggs": [{"id": "2", "type": "date_histogram", "field": "@timestamp",
                        "settings": {"interval": "auto", "min_doc_count": "0"}}],
        "timeField": "@timestamp", "datasource": DS
    }

def bar_panel(pid, title, query, field, x, y, w=12, h=8, color="blue"):
    return {
        "id": pid, "type": "barchart", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS,
        "fieldConfig": {
            "defaults": {"color": {"fixedColor": color, "mode": "fixed"}, "unit": "short"},
            "overrides": []
        },
        "options": {
            "xTickLabelRotation": -45, "barWidth": 0.7,
            "legend": {"displayMode": "hidden"},
            "tooltip": {"mode": "single"}
        },
        "targets": [{
            "refId": "A", "query": query,
            "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": [{"id": "2", "type": "terms", "field": field,
                            "settings": {"size": "10", "order": "desc", "orderBy": "1"}}],
            "timeField": "@timestamp", "datasource": DS
        }]
    }

def pie_panel(pid, title, query, field, x, y, w=8, h=8):
    return {
        "id": pid, "type": "piechart", "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS,
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}, "overrides": []},
        "options": {
            "pieType": "donut",
            "legend": {"placement": "right", "displayMode": "table", "values": ["value", "percent"]}
        },
        "targets": [{
            "refId": "A", "query": query,
            "metrics": [{"id": "1", "type": "count"}],
            "bucketAggs": [{"id": "2", "type": "terms", "field": field,
                            "settings": {"size": "10", "order": "desc", "orderBy": "1"}}],
            "timeField": "@timestamp", "datasource": DS
        }]
    }

dashboard = {
    "uid":   "wazuh-security-events",
    "title": "Wazuh - Security Events",
    "tags":  ["wazuh", "security", "siem"],
    "timezone": "browser",
    "refresh":  "1m",
    "time":     {"from": "now-24h", "to": "now"},
    "schemaVersion": 38,
    "panels": [
        # ── Row 1: stat cards ────────────────────────────────────
        stat_panel(1,  "Total Events",          "*",                                          "blue",    0,  0),
        stat_panel(2,  "Auth Failures",         "rule.groups:authentication_failed",          "red",     4,  0),
        stat_panel(3,  "High Severity (>=10)",  "rule.level:>=10",                            "orange",  8,  0),
        stat_panel(4,  "SSH Brute Force",       "rule.groups:sshd AND rule.groups:invalid_login", "dark-red", 12, 0),
        stat_panel(5,  "Windows Events",        "rule.groups:windows",                        "purple",  16, 0),
        stat_panel(6,  "Syslog Events",         "rule.groups:syslog",                         "green",   20, 0),

        # ── Row 2: timeline ──────────────────────────────────────
        timeseries_panel(10, "Security Events Over Time", [
            ts_target("A", "All Events",          "*"),
            ts_target("B", "Auth Failures",       "rule.groups:authentication_failed"),
            ts_target("C", "High Severity (>=10)","rule.level:>=10"),
        ], 0, 4),

        # ── Row 3: top agents + top rules ────────────────────────
        bar_panel(20, "Top 10 Agents by Events",   "*",                       "agent.name",       0,  12, 12, 8, "blue"),
        bar_panel(21, "Top 10 Rules Triggered",    "*",                       "rule.description", 12, 12, 12, 8, "green"),

        # ── Row 4: pies + attack IPs ─────────────────────────────
        pie_panel(30, "Events by Rule Level",  "*",                       "rule.level",   0,  20),
        pie_panel(31, "Top Rule Groups",       "*",                       "rule.groups",  8,  20),
        bar_panel(32, "Top 10 Attack IPs",     "rule.groups:authentication_failed AND data.srcip:*",
                  "data.srcip", 16, 20, 8, 8, "red"),

        # ── Row 5: recent events table ───────────────────────────
        {
            "id": 40, "type": "table", "title": "Recent Security Events (Latest 100)",
            "gridPos": {"x": 0, "y": 28, "w": 24, "h": 10},
            "datasource": DS,
            "options": {"sortBy": [{"displayName": "Time", "desc": True}], "footer": {"show": False}},
            "fieldConfig": {
                "defaults": {"custom": {"width": 0}},
                "overrides": [
                    {"matcher": {"id": "byName", "options": "rule.level"}, "properties": [
                        {"id": "custom.width", "value": 80},
                        {"id": "displayName",  "value": "Level"},
                        {"id": "thresholds",   "value": {"mode": "absolute", "steps": [
                            {"color": "green",  "value": None},
                            {"color": "yellow", "value": 5},
                            {"color": "orange", "value": 10},
                            {"color": "red",    "value": 12}
                        ]}},
                        {"id": "custom.displayMode", "value": "color-background"}
                    ]},
                    {"matcher": {"id": "byName", "options": "agent.name"},       "properties": [{"id": "custom.width", "value": 160}, {"id": "displayName", "value": "Agent"}]},
                    {"matcher": {"id": "byName", "options": "rule.description"}, "properties": [{"id": "custom.width", "value": 420}, {"id": "displayName", "value": "Rule"}]},
                    {"matcher": {"id": "byName", "options": "data.srcip"},       "properties": [{"id": "custom.width", "value": 140}, {"id": "displayName", "value": "Src IP"}]},
                    {"matcher": {"id": "byName", "options": "rule.groups"},      "properties": [{"id": "custom.width", "value": 200}, {"id": "displayName", "value": "Groups"}]}
                ]
            },
            "targets": [{
                "refId": "A", "query": "*",
                "metrics": [{"id": "1", "type": "raw_data", "settings": {"size": "100"}}],
                "bucketAggs": [],
                "timeField": "@timestamp",
                "datasource": DS
            }]
        }
    ]
}

print("=== Saving Security Events dashboard ===")
r = api("POST", "/api/dashboards/db", {"dashboard": dashboard, "overwrite": True, "folderId": 0})
print("  Status:", r.get("status", r.get("error")))
print("  URL:   ", "https://grafana.codesec.in" + r.get("url", ""))

print("\n=== All dashboards ===")
for d in api("GET", "/api/search?type=dash-db"):
    print(f"  {d['title']}")
    print(f"    https://grafana.codesec.in{d['url']}")
