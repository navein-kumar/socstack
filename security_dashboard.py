import json, urllib.request, urllib.error, base64

GF = "http://localhost:3000"
AUTH = ("admin", "SocGrafana@2025")
DS_UID = "cfdj6iviw19tsa"  # elasticsearch datasource uid

dashboard = {
    "uid": "wazuh-security-events",
    "title": "Wazuh - Security Events",
    "tags": ["wazuh", "security", "siem"],
    "timezone": "browser",
    "refresh": "1m",
    "time": {"from": "now-24h", "to": "now"},
    "schemaVersion": 38,
    "panels": [

        # Row 1: Stat panels
        {
            "id": 1, "type": "stat", "title": "Total Events (24h)",
            "gridPos": {"x": 0, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none", "textMode": "value"},
            "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "thresholds": {"mode": "absolute", "steps": [{"color": "blue", "value": None}]}}},
            "targets": [{"refId": "A", "query": "*", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [], "timeField": "@timestamp"}]
        },
        {
            "id": 2, "type": "stat", "title": "Critical (Level >= 12)",
            "gridPos": {"x": 4, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "thresholds": {"mode": "absolute", "steps": [{"color": "red", "value": None}]}}},
            "targets": [{"refId": "A", "query": "rule.level:>=12", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [], "timeField": "@timestamp"}]
        },
        {
            "id": 3, "type": "stat", "title": "High Severity (Level 10-11)",
            "gridPos": {"x": 8, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "thresholds": {"mode": "absolute", "steps": [{"color": "orange", "value": None}]}}},
            "targets": [{"refId": "A", "query": "rule.level:[10 TO 11]", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [], "timeField": "@timestamp"}]
        },
        {
            "id": 4, "type": "stat", "title": "Auth Failures",
            "gridPos": {"x": 12, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "options": {"reduceOptions": {"calcs": ["count"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "thresholds": {"mode": "absolute", "steps": [{"color": "red", "value": None}]}}},
            "targets": [{"refId": "A", "query": "rule.groups:authentication_failed", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [], "timeField": "@timestamp"}]
        },
        {
            "id": 5, "type": "stat", "title": "Active Agents",
            "gridPos": {"x": 16, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "options": {"reduceOptions": {"calcs": ["sum"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]}}},
            "targets": [{"refId": "A", "query": "*", "metrics": [{"id": "1", "type": "cardinality", "field": "agent.name"}], "bucketAggs": [], "timeField": "@timestamp"}]
        },
        {
            "id": 6, "type": "stat", "title": "Unique Attack IPs",
            "gridPos": {"x": 20, "y": 0, "w": 4, "h": 4},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "options": {"reduceOptions": {"calcs": ["sum"]}, "colorMode": "background", "graphMode": "none"},
            "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "thresholds": {"mode": "absolute", "steps": [{"color": "purple", "value": None}]}}},
            "targets": [{"refId": "A", "query": "rule.groups:authentication_failed AND data.srcip:*", "metrics": [{"id": "1", "type": "cardinality", "field": "data.srcip"}], "bucketAggs": [], "timeField": "@timestamp"}]
        },

        # Row 2: Events over time
        {
            "id": 10, "type": "timeseries", "title": "Security Events Over Time",
            "gridPos": {"x": 0, "y": 4, "w": 24, "h": 8},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 10}}},
            "options": {"tooltip": {"mode": "multi"}},
            "targets": [
                {"refId": "A", "alias": "All Events", "query": "*", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [{"type": "date_histogram", "field": "@timestamp", "id": "2", "settings": {"interval": "auto", "min_doc_count": "0"}}], "timeField": "@timestamp"},
                {"refId": "B", "alias": "Critical (Level >=12)", "query": "rule.level:>=12", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [{"type": "date_histogram", "field": "@timestamp", "id": "2", "settings": {"interval": "auto", "min_doc_count": "0"}}], "timeField": "@timestamp"},
                {"refId": "C", "alias": "Auth Failures", "query": "rule.groups:authentication_failed", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [{"type": "date_histogram", "field": "@timestamp", "id": "2", "settings": {"interval": "auto", "min_doc_count": "0"}}], "timeField": "@timestamp"}
            ]
        },

        # Row 3: Top agents + Top rules
        {
            "id": 20, "type": "barchart", "title": "Top 10 Agents by Event Count",
            "gridPos": {"x": 0, "y": 12, "w": 12, "h": 8},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}},
            "options": {"xTickLabelRotation": -45, "barWidth": 0.7},
            "targets": [{"refId": "A", "query": "*", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [{"type": "terms", "field": "agent.name", "id": "2", "settings": {"size": "10", "order": "desc", "orderBy": "1"}}], "timeField": "@timestamp"}]
        },
        {
            "id": 21, "type": "barchart", "title": "Top 10 Rules Triggered",
            "gridPos": {"x": 12, "y": 12, "w": 12, "h": 8},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}},
            "options": {"xTickLabelRotation": -45, "barWidth": 0.7},
            "targets": [{"refId": "A", "query": "*", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [{"type": "terms", "field": "rule.description", "id": "2", "settings": {"size": "10", "order": "desc", "orderBy": "1"}}], "timeField": "@timestamp"}]
        },

        # Row 4: Pie charts + Top IPs
        {
            "id": 30, "type": "piechart", "title": "Events by Severity Level",
            "gridPos": {"x": 0, "y": 20, "w": 8, "h": 8},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "options": {"pieType": "donut", "legend": {"placement": "right", "displayMode": "table", "values": ["value", "percent"]}},
            "targets": [{"refId": "A", "query": "*", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [{"type": "terms", "field": "rule.level", "id": "2", "settings": {"size": "15", "order": "desc", "orderBy": "1"}}], "timeField": "@timestamp"}]
        },
        {
            "id": 31, "type": "piechart", "title": "Top Rule Groups",
            "gridPos": {"x": 8, "y": 20, "w": 8, "h": 8},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "options": {"pieType": "donut", "legend": {"placement": "right", "displayMode": "table", "values": ["value", "percent"]}},
            "targets": [{"refId": "A", "query": "*", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [{"type": "terms", "field": "rule.groups", "id": "2", "settings": {"size": "10", "order": "desc", "orderBy": "1"}}], "timeField": "@timestamp"}]
        },
        {
            "id": 32, "type": "barchart", "title": "Top 10 Attack Source IPs",
            "gridPos": {"x": 16, "y": 20, "w": 8, "h": 8},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "fieldConfig": {"defaults": {"color": {"fixedColor": "red", "mode": "fixed"}}},
            "options": {"xTickLabelRotation": -45},
            "targets": [{"refId": "A", "query": "rule.groups:authentication_failed AND data.srcip:*", "metrics": [{"id": "1", "type": "count"}], "bucketAggs": [{"type": "terms", "field": "data.srcip", "id": "2", "settings": {"size": "10", "order": "desc", "orderBy": "1"}}], "timeField": "@timestamp"}]
        },

        # Row 5: Recent alerts table
        {
            "id": 40, "type": "table", "title": "Recent Security Events (Latest 50)",
            "gridPos": {"x": 0, "y": 28, "w": 24, "h": 10},
            "datasource": {"type": "elasticsearch", "uid": DS_UID},
            "options": {"sortBy": [{"displayName": "Time", "desc": True}]},
            "fieldConfig": {
                "defaults": {"custom": {"width": 0}},
                "overrides": [
                    {"matcher": {"id": "byName", "options": "rule.level"}, "properties": [
                        {"id": "custom.width", "value": 90},
                        {"id": "displayName", "value": "Level"},
                        {"id": "thresholds", "value": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 5}, {"color": "orange", "value": 10}, {"color": "red", "value": 12}]}},
                        {"id": "custom.displayMode", "value": "color-background"}
                    ]},
                    {"matcher": {"id": "byName", "options": "agent.name"}, "properties": [{"id": "custom.width", "value": 160}, {"id": "displayName", "value": "Agent"}]},
                    {"matcher": {"id": "byName", "options": "rule.description"}, "properties": [{"id": "custom.width", "value": 420}, {"id": "displayName", "value": "Rule"}]},
                    {"matcher": {"id": "byName", "options": "data.srcip"}, "properties": [{"id": "custom.width", "value": 140}, {"id": "displayName", "value": "Source IP"}]},
                    {"matcher": {"id": "byName", "options": "rule.groups"}, "properties": [{"id": "custom.width", "value": 200}, {"id": "displayName", "value": "Groups"}]}
                ]
            },
            "targets": [{"refId": "A", "query": "*", "metrics": [{"id": "1", "type": "raw_data", "settings": {"size": "50"}}], "bucketAggs": [], "timeField": "@timestamp"}]
        }
    ]
}

token = base64.b64encode(f"{AUTH[0]}:{AUTH[1]}".encode()).decode()
payload = json.dumps({"dashboard": dashboard, "overwrite": True, "folderId": 0}).encode()
req = urllib.request.Request(
    f"{GF}/api/dashboards/db",
    data=payload,
    headers={"Content-Type": "application/json", "Authorization": f"Basic {token}"},
    method="POST"
)
try:
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
        print("Status:", result.get("status"))
        print("URL:   ", "https://grafana.codesec.in" + result.get("url", ""))
except urllib.error.HTTPError as e:
    print("Error:", e.code, e.read().decode())
