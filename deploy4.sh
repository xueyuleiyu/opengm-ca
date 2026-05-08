#!/bin/bash
set -e
# export SSHPASS='你的SSH密码'  # 请设置环境变量
REMOTE='${REMOTE_USER}@${REMOTE_HOST}'  # 请设置环境变量
LOCAL_DIR='/mnt/c/Users/sunxu/ca-system-design/opengm-ca'
REPO_DIR='/root/opengm-ca'

echo '=== Sync code via scp ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" "rm -rf $REPO_DIR; mkdir -p $REPO_DIR"
sshpass -e scp -o StrictHostKeyChecking=no -r "$LOCAL_DIR"/* "$REMOTE:$REPO_DIR/"

echo ''
echo '=== Build on remote ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" "cd $REPO_DIR && /usr/local/go/bin/go build -o ca-server-linux ./cmd/ca-server/main.go 2>&1"

echo ''
echo '=== Deploy: stop old, copy new, start ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" "
cd $REPO_DIR
pkill -f 'ca-server' 2>/dev/null || true
sleep 1
cp ca-server-linux /opt/opengm-ca/ca-server
chown root:root /opt/opengm-ca/ca-server
chmod 700 /opt/opengm-ca/ca-server
cd /opt/opengm-ca
nohup ./ca-server -config ./configs/config.yaml > /var/log/opengm-ca.log 2>&1 &
sleep 2
ps aux | grep ca-server | grep -v grep
"

echo ''
echo '=== Health check ==='
sshpass -e ssh -o StrictHostKeyChecking=no "$REMOTE" "curl -s http://127.0.0.1:8443/health"

echo ''
echo '=== Done ==='
