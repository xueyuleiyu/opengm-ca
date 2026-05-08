#!/bin/bash
set -e
# export SSHPASS='${SSHPASS}'  # 请设置环境变量
REMOTE='${REMOTE_USER}@${REMOTE_HOST}'  # 请设置环境变量

echo '=== 1. Login (admin/SYS_ADMIN) ==='
TOKEN=$(sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "curl -s -X POST http://127.0.0.1:8443/api/v1/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"<your_password>\"}'" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
echo "Token: ${TOKEN:0:40}..."

echo ''
echo '=== 2. HSM Status (SYS_ADMIN now has HSM_MANAGE? No, SEC_ADMIN only) ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "curl -s http://127.0.0.1:8443/api/v1/hsm/status -H 'Authorization: Bearer $TOKEN'"

echo ''
echo '=== 3. List Operators (SYS_ADMIN has USER_MANAGE) ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "curl -s http://127.0.0.1:8443/api/v1/operators -H 'Authorization: Bearer $TOKEN'"

echo ''
echo '=== 4. Init Default Admins ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "curl -s -X POST http://127.0.0.1:8443/api/v1/auth/init-admins -H 'Authorization: Bearer $TOKEN'"

echo ''
echo '=== 5. List Operators After Init ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "curl -s http://127.0.0.1:8443/api/v1/operators -H 'Authorization: Bearer $TOKEN'"

echo ''
echo '=== 6. Frontend Title ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "curl -s http://127.0.0.1:8443/ | grep -o '<title>.*</title>'"

echo ''
echo '=== Done ==='
