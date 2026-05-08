#!/bin/bash
set -e

REPO_DIR="/root/opengm-ca"
REMOTE="${REMOTE_USER}@${REMOTE_HOST}"  # 请设置环境变量
SSHPASS="${SSHPASS}"  # 请设置环境变量

echo "=== 1. Sync local code to remote ==="
# Use rsync over sshpass
sshpass -p "$SSHPASS" rsync -avz --delete \
  --exclude='.git' --exclude='ca-server-linux' --exclude='*.exe' \
  -e "ssh -o StrictHostKeyChecking=no" \
  /mnt/c/Users/sunxu/ca-system-design/opengm-ca/ \
  "$REMOTE:$REPO_DIR/"

echo ""
echo "=== 2. Build on remote ==="
sshpass -p "$SSHPASS" ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "cd $REPO_DIR && /usr/local/go/bin/go build -o ca-server-linux ./cmd/ca-server/main.go 2>&1"

echo ""
echo "=== 3. Deploy binary and restart ==="
sshpass -p "$SSHPASS" ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "cd $REPO_DIR && systemctl stop opengm-ca 2>/dev/null; \
   cp ca-server-linux /opt/opengm-ca/ca-server; \
   chown root:root /opt/opengm-ca/ca-server; \
   chmod 700 /opt/opengm-ca/ca-server; \
   systemctl start opengm-ca; \
   sleep 2; \
   systemctl status opengm-ca --no-pager"

echo ""
echo "=== 4. Verify ==="
sshpass -p "$SSHPASS" ssh -o StrictHostKeyChecking=no "$REMOTE" \
  "curl -s http://127.0.0.1:8443/health | head -c 80"

echo ""
echo "=== Done ==="
