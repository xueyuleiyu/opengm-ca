#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

echo "=== 1. Login ==="
TOKEN=$(curl -s -X POST http://127.0.0.1:8443/api/v1/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"<your_password>"}' | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
echo "Token: ${TOKEN:0:40}..."

echo ""
echo "=== 2. HSM Status ==="
curl -s http://127.0.0.1:8443/api/v1/hsm/status -H "Authorization: Bearer $TOKEN" | head -c 100

echo ""
echo "=== 3. Generate HSM Key ==="
curl -s -X POST http://127.0.0.1:8443/api/v1/hsm/keys -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"algorithm":"SM2","key_type":"SIGN"}' | head -c 80

echo ""
echo "=== 4. List HSM Keys ==="
curl -s http://127.0.0.1:8443/api/v1/hsm/keys -H "Authorization: Bearer $TOKEN" | head -c 100

echo ""
echo "=== 5. List Operators ==="
curl -s http://127.0.0.1:8443/api/v1/operators -H "Authorization: Bearer $TOKEN" | head -c 100

echo ""
echo "=== 6. Frontend Title ==="
curl -s http://127.0.0.1:8443/ | grep -o "<title>.*</title>"

echo ""
echo "=== 7. HSM Files ==="
ls -la /opt/opengm-ca/data/hsm/ 2>/dev/null || echo "No HSM files yet"

echo ""
echo "=== Done ==="
