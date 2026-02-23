#!/bin/bash
GF="http://localhost:3000"
AUTH="admin:SocGrafana@2025"

echo "=== 1. All datasources ==="
curl -sk -u "$AUTH" "$GF/api/datasources" | python3 -m json.tool

echo ""
echo "=== 2. Health check datasource ID 4 ==="
curl -sk -u "$AUTH" -X POST "$GF/api/datasources/4/health" | python3 -m json.tool

echo ""
echo "=== 3. Health check datasource ID 1 (OpenSearch) ==="
curl -sk -u "$AUTH" -X POST "$GF/api/datasources/1/health" | python3 -m json.tool

echo ""
echo "=== 4. Proxy test through Grafana to indexer ==="
curl -sk -u "$AUTH" \
  "$GF/api/datasources/proxy/uid/cfdj6iviw19tsa/wazuh-alerts-4.x-*/_count"

echo ""
echo "=== 5. Check Grafana logs for errors ==="
docker logs socstack-grafana --tail 20 2>&1 | grep -i "error\|warn\|datasource" | tail -10
