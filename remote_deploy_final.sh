#!/bin/bash
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

cd /opt/opengm-ca
export PATH=/usr/local/go/bin:$PATH
export GOPROXY=https://goproxy.cn,direct

echo "=== Build ==="
go build -o ca-server ./cmd/ca-server

echo "=== Create HSM dir ==="
mkdir -p /opt/opengm-ca/data/hsm
chmod 700 /opt/opengm-ca/data/hsm

echo "=== Restart ==="
pkill -f "ca-server -config" || true
sleep 1
nohup ./ca-server -config ./configs/config.yaml > /var/log/opengm-ca.log 2>&1 &
sleep 2

echo "=== Check ==="
ps aux | grep ca-server | grep -v grep || true
curl -s http://127.0.0.1:8443/health | head -c 80
echo ""

echo "=== Update DB roles ==="
su - omm -c "gsql -d opengm_ca -U ca_admin -W ${DB_PASSWORD} -p 5432 -c 'ALTER TABLE operators DROP CONSTRAINT IF EXISTS operators_role_check;'" 2>&1 || true
su - omm -c "gsql -d opengm_ca -U ca_admin -W ${DB_PASSWORD} -p 5432 -c \"UPDATE operators SET role = 'SYS_ADMIN' WHERE username = 'admin' AND role = 'SUPER_ADMIN';\"" 2>&1 || true
su - omm -c "gsql -d opengm_ca -U ca_admin -W ${DB_PASSWORD} -p 5432 -c 'SELECT id, username, role FROM operators;'" 2>&1 | grep -v ulimit

echo "=== Done ==="
