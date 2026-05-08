#!/bin/bash
set -e
# export SSHPASS='你的SSH密码'  # 请设置环境变量
REPO_DIR='/root/opengm-ca'
REMOTE='${REMOTE_USER}@${REMOTE_HOST}'  # 请设置环境变量
LOCAL_DIR='/mnt/c/Users/sunxu/ca-system-design/opengm-ca'

echo '=== Sync code to remote ==='
sshpass -e rsync -avz --delete \
  --exclude='.git' --exclude='ca-server-linux' --exclude='*.exe' \
  -e 'ssh -o StrictHostKeyChecking=no' \
  "$LOCAL_DIR/" "$REMOTE:$REPO_DIR/"

echo ''
echo '=== Build on remote ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "cd $REPO_DIR && /usr/local/go/bin/go build -o ca-server-linux ./cmd/ca-server/main.go 2>&1"

echo ''
echo '=== Deploy and restart ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "cd $REPO_DIR && systemctl stop opengm-ca 2>/dev/null; cp ca-server-linux /opt/opengm-ca/ca-server; chown root:root /opt/opengm-ca/ca-server; chmod 700 /opt/opengm-ca/ca-server; systemctl start opengm-ca; sleep 2; systemctl status opengm-ca --no-pager"

echo ''
echo '=== Health check ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "curl -s http://127.0.0.1:8443/health"

echo ''
echo '=== Done ==='
