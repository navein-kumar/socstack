# SOC Stack - Post-Deployment UI Configuration Guide

After running `post-deploy.py`, the following manual UI configurations are required.

All credentials are in `/opt/socstack/.env.deployed` on the server.

---

## A. TheHive - Cortex Server Integration

1. Login to **TheHive** → `https://hive.codesec.in`
   - User: `admin@thehive.local` / *(see `.env.deployed` → `THEHIVE_ADMIN_PASSWORD`)*
2. Go to **Platform Management** → **Cortex Servers** → **Add Server**
3. Fill in:

| Field | Value |
|-------|-------|
| Server Name | `Cortex-CODESEC` |
| URL | `http://socstack-cortex:9001` |
| API Key | *(see `.env.deployed` → `CORTEX_API_KEY`)* |
| Check Certificate Authority | **DISABLE** (toggle OFF) |
| Disable hostname verification | **ENABLE** (toggle ON) |

4. Click **Confirm**

---

## B. TheHive - MISP Server Integration

1. In **TheHive** → **Platform Management** → **MISP Servers** → **Add Server**
2. Fill in:

| Field | Value |
|-------|-------|
| Name | `MISP-CODESEC` |
| URL | `https://socstack-misp-core:443` |
| API Key | *(see `.env.deployed` → `MISP_API_KEY`)* |
| Skip SSL verification | **Yes** |
| Purpose | Import and Export |
| Organisation | your org name |

3. Click **Save** → **Sync Now**

---

## C. Cortex - Enable & Configure Analyzers

1. Login to **Cortex** → `https://cortex.codesec.in`
   - User: *(see `.env.deployed` → `CORTEX_ORG_ADMIN` / `CORTEX_ADMIN_PASSWORD`)*
2. Go to **Organization** → **Analyzers** → **Refresh** (click the refresh icon)
3. Wait for the analyzer list to load

### Install & Configure VirusTotal Analyzer

1. In the Analyzers list, search for **VirusTotal**
2. Click **Enable** on `VirusTotal_GetReport_3_1`
3. After enabling, click the **Edit** (pencil) icon on the analyzer
4. Fill in:

| Field | Value |
|-------|-------|
| key | Your VirusTotal API key |
| polling_interval | `60` |
| proxies | *(leave empty unless behind proxy)* |

5. Click **Save**
6. Repeat for other VirusTotal analyzers if needed:
   - `VirusTotal_Scan_3_1` — Submit files/URLs for scanning
   - `VirusTotal_Download_3_1` — Download samples

> **Get a VirusTotal API key:** Sign up at https://www.virustotal.com → Profile → API Key (free tier: 4 requests/min)

### Other Recommended Analyzers

| Analyzer | Purpose | API Key Source |
|----------|---------|----------------|
| AbuseIPDB_1_0 | IP reputation check | https://www.abuseipdb.com |
| OTXQuery_2_0 | AlienVault OTX threat intel | https://otx.alienvault.com |
| Shodan_DNSResolve_2_0 | DNS/IP intelligence | https://www.shodan.io |
| URLhaus_2_0 | Malicious URL check | Free (no key needed) |
| FileInfo_8_0 | File analysis | Free (no key needed) |

For each analyzer: **Enable** → **Edit** → enter API key → **Save**

---

---

## E. Wazuh Dashboard - SSO Role Mapping

> **Required** for SSO users to access Wazuh features with correct permissions.

1. Login to **Wazuh Dashboard** → `https://wazuh.codesec.in`
   - Use basic auth: `admin` / *(see `.env.deployed` → `WAZUH_INDEXER_PASSWORD`)*
2. Go to **Wazuh** → **Security** → **Roles mapping** → **Create role mapping**

### Role Map 1: Admin

| Field | Value |
|-------|-------|
| Role mapping name | `wazuh_admin` |
| Roles | Select all admin permissions (administrator,user_admin,agents_admin,cluster_admin,) |
| Internal users | *(leave empty)* |
| Custom rules | backend_roles → Find → `wazuh_admin` |

### Role Map 2: Read-Only User

| Field | Value |
|-------|-------|
| Role mapping name | `wazuh_read_user` |
| Roles | Select readonly permissions (readonly,cluster_readonly,agent_readonly)  |
| Internal users | *(leave empty)* |
| Custom rules | backend_roles → Find → `wazuh_read_user` |

After creating both mappings, SSO users in the `wazuh_admin` Keycloak group will get admin access, and users in `wazuh_user` group will get read-only access.

---

## F. n8n - Import Wazuh Alert Workflow (Email + TheHive)

1. Login to **n8n** → `https://n8n.codesec.in`
   - User: *(see `.env.deployed` → `N8N_ADMIN_EMAIL` / `N8N_ADMIN_PASSWORD`)*

2. **Create new workflow** → **Import from file**
   - File on server: `/opt/socstack/configs/n8n/1_Wazuh_Email_Alert.json`

3. **Fix Redis connection** (do this first):
   - Click the Redis node → Edit credentials
   - **Host:** `socstack-n8n-redis`
   - **Port:** `6379`
   - **Password:** *(leave empty — no password)*
   - Save & test connection

4. **Setup SMTP email credentials:**
   - Click the **Send email** node → Edit SMTP credentials
   - Configure:
     - **SMTP Host:** your SMTP server
     - **Port:** 587 (or 465 for SSL)
     - **User:** your SMTP username
     - **Password:** your SMTP password
   - Set **From** email address
   - Set **To** email address(es)

### Configure TheHive Node (Alert Creation)

5. **Generate TheHive API Key for analyst account:**
   - Login to **TheHive** → `https://hive.codesec.in`
     - User: `admin@thehive.local` / *(see `.env.deployed` → `THEHIVE_ADMIN_PASSWORD`)*
   - Go to **Organisation** → **Users** → find `analyst@codesec.in`
   - Click **Create API Key** → **Reveal** → copy the API key
   - ⚠️ **Save this key** — you cannot view it again after closing the dialog

6. **Configure TheHive credentials in n8n:**
   - Click the **TheHive** node in the workflow → Edit credentials
   - Click **Create New Credential** → select **TheHive API**
   - Fill in:

| Field | Value |
|-------|-------|
| API Key | *(TheHive analyst API key from step 5)* |
| URL | `http://socstack-thehive:9000` |
| Ignore SSL Issues | **ON** |

   - Click **Save** → test connection should succeed

7. **Verify TheHive node configuration:**
   - The TheHive node should be set to **Create Alert**
   - Key fields mapped from Wazuh alert data:
     - **Title** → Wazuh rule description
     - **Description** → Alert details (source IP, agent, rule info)
     - **Severity** → Mapped from Wazuh rule level
     - **Type** → `wazuh_alert`
     - **Source** → `Wazuh-SIEM`
   - The incident response team will pick up alerts in TheHive for further investigation

> **TheHive Analyst Account:**
> - User: `analyst@codesec.in` / *(see `.env.deployed` → `THEHIVE_ANALYST_PASSWORD`)*
> - Profile: `analyst` — can create/manage alerts & cases
> - Organisation: `CODESEC`

### Enable Workflow & Connect Wazuh

8. **Enable the workflow** (toggle ON at top-right)

9. **Copy the Webhook URL:**
   - Click the **Webhook** node
   - Copy the **Production URL** (e.g., `https://n8n.codesec.in/webhook/xxxxx`)

10. **Update Wazuh manager config with new webhook URL:**
    - Edit on server: `/opt/socstack/configs/wazuh/wazuh_cluster/wazuh_manager.conf`
    - Find the `<integration>` section for `custom-n8n`
    - Replace the `<hook_url>` value with your new webhook URL:
    ```xml
    <integration>
      <name>custom-n8n</name>
      <hook_url>https://n8n.codesec.in/webhook/YOUR-NEW-WEBHOOK-ID</hook_url>
      ...
    </integration>
    ```

11. **Restart Wazuh manager** to pick up the new webhook URL:
    ```bash
    docker restart socstack-wazuh-manager
    ```

12. **Test the full pipeline:**
    - Trigger a Wazuh alert (e.g., failed SSH login)
    - Verify **email notification** arrives
    - Verify **TheHive alert** is created at `https://hive.codesec.in` → **Alerts** page
    - Incident team can then promote alerts to **Cases** for investigation

---

## G. Grafana - Datasource & Dashboards

The **Wazuh-OpenSearch** datasource is auto-provisioned via `configs/grafana/provisioning/datasources/datasources.yml`.

### Verify Datasource Connection

1. Login to **Grafana** → `https://grafana.codesec.in`
   - User: `admin` / *(see `.env.deployed` → `GF_ADMIN_PASSWORD`)*
2. Go to **Connections** → **Data sources** → **Wazuh-OpenSearch**
3. Click **Save & Test** — should show "Data source connected and target index-pattern exists"

### If Auto-Provisioned Datasource Fails

If you see "Plugin not found" or connection errors, add the datasource manually:

1. Go to **Connections** → **Data sources** → **Add data source**
2. Search for **OpenSearch** (requires `grafana-opensearch-datasource` plugin)
3. Fill in:

| Field | Value |
|-------|-------|
| Name | `Wazuh-OpenSearch` |
| URL | `https://wazuh.indexer:9200` |
| Auth → Basic auth | **ON** |
| User | `admin` |
| Password | *(see `.env.deployed` → `WAZUH_INDEXER_PASSWORD`)* |
| TLS → Skip TLS Verify | **ON** |
| OpenSearch details → Version | `2.19.1` |
| OpenSearch details → Index name | `wazuh-alerts-*` |
| OpenSearch details → Time field | `timestamp` |

4. Click **Save & Test**

> **Note:** If the OpenSearch plugin is missing, install it on the server:
> ```bash
> # Download plugin (requires internet access from server)
> curl -sL -o /tmp/opensearch-plugin.zip \
>   https://github.com/grafana/opensearch-datasource/releases/download/v2.22.1/grafana-opensearch-datasource-2.22.1.linux_amd64.zip
> unzip -qo /tmp/opensearch-plugin.zip -d /opt/socstack/data/grafana/plugins/
> chown -R 472:0 /opt/socstack/data/grafana/plugins/
> docker restart socstack-grafana
> ```

### Create Dashboards

1. Go to **Dashboards** → **Import** → create custom dashboards using the Wazuh-OpenSearch datasource
2. Useful index patterns:
   - `wazuh-alerts-*` — Security alerts
   - `wazuh-monitoring-*` — Agent monitoring
   - `wazuh-statistics-*` — Manager statistics

---

## Quick Reference: Service URLs

| Service | URL | Purpose |
|---------|-----|---------|
| Wazuh Dashboard | https://wazuh.codesec.in | SIEM Dashboard |
| Keycloak SSO | https://sso.codesec.in | SSO Admin Console |
| n8n | https://n8n.codesec.in | Workflow Automation |
| MISP | https://cti.codesec.in | Threat Intelligence |
| TheHive | https://hive.codesec.in | Case Management |
| Cortex | https://cortex.codesec.in | Analysis Engine |
| Grafana | https://grafana.codesec.in | Visualization |
| NPM | https://npm.codesec.in | Proxy Manager |

---

## Quick Reference: Key Values from `.env.deployed`

| Key | Used In |
|-----|---------|
| `CORTEX_API_KEY` | TheHive → Cortex server config |
| `MISP_API_KEY` | TheHive → MISP server config |
| `THEHIVE_ADMIN_PASSWORD` | TheHive admin login |
| `THEHIVE_ANALYST_USER` | TheHive analyst account (n8n API key) |
| `THEHIVE_ANALYST_PASSWORD` | TheHive analyst login |
| `CORTEX_ADMIN_PASSWORD` | Cortex login |
| `WAZUH_INDEXER_PASSWORD` | Wazuh Dashboard basic auth login |
| `N8N_ADMIN_EMAIL` / `N8N_ADMIN_PASSWORD` | n8n login |
| `GF_ADMIN_PASSWORD` | Grafana login |
