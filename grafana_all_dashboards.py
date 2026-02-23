#!/usr/bin/env python3
"""
Import all available Wazuh Grafana dashboards
Fixes underscore field names -> dot notation to match native Wazuh indexer fields
"""
import json, urllib.request, urllib.error, base64, re

GF   = "http://localhost:3000"
USER = "admin"
PASS = "SocGrafana@2025"
ES_UID = "cfdj6iviw19tsa"   # elasticsearch datasource - confirmed working

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

def download_dashboard(dash_id):
    url = f"https://grafana.com/api/dashboards/{dash_id}/revisions/latest/download"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def fix_fields(obj):
    """
    Fix two things in dashboard JSON:
    1. Underscore field names -> dot notation (Graylog pipeline artifact)
       agent_name -> agent.name, rule_level -> rule.level, etc.
    2. Remap all datasources to our elasticsearch DS
    """
    if isinstance(obj, str):
        # Fix underscore -> dot in field references inside query strings
        # Common Wazuh fields that dashboards use with underscore
        replacements = [
            ("agent_name",          "agent.name"),
            ("agent_id",            "agent.id"),
            ("agent_ip",            "agent.ip"),
            ("rule_level",          "rule.level"),
            ("rule_id",             "rule.id"),
            ("rule_description",    "rule.description"),
            ("rule_groups",         "rule.groups"),
            ("rule_mitre_id",       "rule.mitre.id"),
            ("rule_mitre_tactic",   "rule.mitre.tactic"),
            ("rule_mitre_technique","rule.mitre.technique"),
            ("rule_pci_dss",        "rule.pci_dss"),
            ("rule_gdpr",           "rule.gdpr"),
            ("rule_nist_800_53",    "rule.nist_800_53"),
            ("rule_hipaa",          "rule.hipaa"),
            ("rule_tsc",            "rule.tsc"),
            ("data_srcip",          "data.srcip"),
            ("data_win_system_eventID","data.win.system.eventID"),
            ("syscheck_path",       "syscheck.path"),
            ("syscheck_event",      "syscheck.event"),
            ("vulnerability_cve",   "vulnerability.cve"),
            ("vulnerability_severity","vulnerability.severity"),
            ("vulnerability_package_name","vulnerability.package.name"),
            ("location",            "location"),
        ]
        for old, new in replacements:
            obj = obj.replace(f'"{old}"', f'"{new}"')
            obj = obj.replace(f"'{old}'", f"'{new}'")
        return obj
    elif isinstance(obj, dict):
        # Fix datasource references
        if "datasource" in obj and isinstance(obj["datasource"], dict):
            obj["datasource"] = {"type": "elasticsearch", "uid": ES_UID}
        if "datasource" in obj and isinstance(obj["datasource"], str):
            obj["datasource"] = ES_UID
        return {k: fix_fields(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [fix_fields(i) for i in obj]
    return obj

def import_dashboard(dash_id, name):
    print(f"\n=== Importing {dash_id}: {name} ===")
    try:
        dash = download_dashboard(dash_id)
    except Exception as e:
        print(f"  ✗ Download failed: {e}")
        return

    # Remove id so Grafana assigns a new one (avoid conflicts)
    dash.pop("id", None)

    # Fix all field names and datasource references
    dash = fix_fields(dash)

    # Build inputs mapping for all __inputs
    inputs = []
    for inp in dash.get("__inputs", []):
        inputs.append({
            "name":     inp.get("name"),
            "type":     "datasource",
            "pluginId": "elasticsearch",
            "value":    "elasticsearch"
        })

    # If no inputs defined, still works - Grafana uses the remapped datasource UIDs
    result = api("POST", "/api/dashboards/import", {
        "dashboard": dash,
        "overwrite": True,
        "inputs":    inputs,
        "folderId":  0
    })

    status = result.get("status", "")
    url    = result.get("importedUrl", result.get("url", ""))
    err    = result.get("error", result.get("body", ""))

    if url:
        print(f"  ✓ {status} → https://grafana.codesec.in{url}")
    else:
        print(f"  ✗ Failed: {err[:200]}")

# ── Import all dashboards ──────────────────────────────────────────────────────
dashboards = [
    (22448, "WAZUH SUMMARY"),
    (22449, "WAZUH - MITRE ATT&CK"),
    (22450, "WAZUH - SYSTEM SECURITY AUDIT"),
    (22451, "WAZUH - SYSTEM VULNERABILITIES"),
    (22453, "WAZUH - COMPLIANCE"),
    (23072, "WAZUH - FIM (File Integrity Monitoring)"),
    (24888, "WAZUH - SYSTEM VULNERABILITIES v2"),
]

for did, name in dashboards:
    import_dashboard(did, name)

# ── Final list ─────────────────────────────────────────────────────────────────
print("\n\n====================================")
print("  ALL DASHBOARDS AVAILABLE")
print("====================================")
for d in api("GET", "/api/search?type=dash-db"):
    print(f"  {d['title']}")
    print(f"    https://grafana.codesec.in{d['url']}")
print("\nLogin: admin / SocGrafana@2025")
print("Set time range: Last 24h or Last 7 days")
