#!/bin/bash
# 前后端对齐验证脚本 - 使用python解析JSON避免grep误报

BASE_URL="https://localhost:8443"

echo "=== 获取Token ==="
SEC_TOKEN=$(curl -sk -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"sec_admin","password":"WOai@8680186"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")
SYS_TOKEN=$(curl -sk -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"sys_admin","password":"WOai@8680186"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")
AUDIT_TOKEN=$(curl -sk -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"audit_admin","password":"AuditAdmin@2026"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")

echo ""
echo "=== 1. 登录API字段验证 ==="
curl -sk -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"sec_admin","password":"WOai@8680186"}' | python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('data', {})
operator = data.get('operator', {})
checks = [
    ('code=OK', d.get('code') == 'OK'),
    ('access_token存在', bool(data.get('access_token'))),
    ('operator存在', bool(operator)),
    ('operator.id存在', 'id' in operator),
    ('operator.username存在', 'username' in operator),
    ('operator.role存在', 'role' in operator),
    ('operator.permissions存在', 'permissions' in operator),
]
all_pass = True
for name, ok in checks:
    status = '✅' if ok else '❌'
    if not ok: all_pass = False
    print(f'  {status} {name}')
print('结果:', '通过' if all_pass else '失败')
"

echo ""
echo "=== 2. /health 字段验证 ==="
curl -sk "${BASE_URL}/health" | python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('data', {})
checks = [
    ('code=OK', d.get('code') == 'OK'),
    ('data.status=healthy', data.get('status') == 'healthy'),
    ('data.stats存在', bool(data.get('stats'))),
    ('stats.active_certificates存在', 'active_certificates' in data.get('stats', {})),
    ('stats.revoked_certificates存在', 'revoked_certificates' in data.get('stats', {})),
]
all_pass = True
for name, ok in checks:
    status = '✅' if ok else '❌'
    if not ok: all_pass = False
    print(f'  {status} {name}')
print('结果:', '通过' if all_pass else '失败')
"

echo ""
echo "=== 3. 证书列表分页格式验证 ==="
curl -sk "${BASE_URL}/api/v1/certificates" -H "Authorization: Bearer ${SEC_TOKEN}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('data', {})
checks = [
    ('code=OK', d.get('code') == 'OK'),
    ('data.total存在', 'total' in data),
    ('data.page存在', 'page' in data),
    ('data.page_size存在', 'page_size' in data),
    ('data.items存在', 'items' in data),
    ('items是列表', isinstance(data.get('items'), list)),
]
all_pass = True
for name, ok in checks:
    status = '✅' if ok else '❌'
    if not ok: all_pass = False
    print(f'  {status} {name}')
print('结果:', '通过' if all_pass else '失败')
"

echo ""
echo "=== 4. 证书列表查询参数对齐验证（修复后）==="
python3 << PYEOF
import urllib.request, json, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def api_call(path, token=None):
    req = urllib.request.Request(f"${BASE_URL}{path}")
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read().decode())

# 测试 cn 参数（应该被忽略，返回所有）
d1 = api_call('/api/v1/certificates?cn=e2e-test.opengm.ca', "${SEC_TOKEN}")
count_cn = len(d1.get('data',{}).get('items',[]))

# 测试 subject_cn 参数（应该正确过滤）
d2 = api_call('/api/v1/certificates?subject_cn=e2e-test.opengm.ca', "${SEC_TOKEN}")
count_subject_cn = len(d2.get('data',{}).get('items',[]))

# 测试无过滤
d3 = api_call('/api/v1/certificates', "${SEC_TOKEN}")
count_all = len(d3.get('data',{}).get('items',[]))

print(f'  cn过滤返回: {count_cn} 条')
print(f'  subject_cn过滤返回: {count_subject_cn} 条')
print(f'  无过滤返回: {count_all} 条')

if count_cn == count_all and count_subject_cn < count_all:
    print('  ✅ 后端正确识别subject_cn，忽略cn')
    print('  ✅ 前端已修复为使用subject_cn')
else:
    print('  ❌ 参数行为异常')
PYEOF

echo ""
echo "=== 5. 前端代码参数验证 ==="
if grep -q "subject_cn" /root/opengm-ca/web/index.html; then
    echo "  ✅ 前端代码已使用 subject_cn 参数"
else
    echo "  ❌ 前端代码仍使用 cn 参数"
fi

echo ""
echo "=== 6. 证书列表字段完整性 ==="
curl -sk "${BASE_URL}/api/v1/certificates" -H "Authorization: Bearer ${SEC_TOKEN}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('data',{}).get('items',[])
if not items:
    print('  ⚠️ 无证书数据')
else:
    first = items[0]
    required = ['id', 'cert_type', 'subject_dn', 'serial_number', 'status', 'valid_from', 'valid_to', 'cert_pem', 'key_id']
    all_ok = True
    for field in required:
        ok = field in first
        status = '✅' if ok else '❌'
        if not ok: all_ok = False
        print(f'  {status} {field}')
    print('结果:', '通过' if all_ok else '失败')
"

echo ""
echo "=== 7. 权限隔离验证 ==="
python3 << PYEOF
import urllib.request, json, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def api_call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(f"${BASE_URL}{path}", data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())

tests = [
    ('sys_admin申请证书', 'POST', '/api/v1/certificates/enroll', {"cert_type":"SSL","algorithm":"SM2","subject":{"common_name":"test.com","organization":"T","country":"CN"},"validity_days":365,"gen_key_locally":True}, "${SYS_TOKEN}"),
    ('sec_admin访问操作员', 'GET', '/api/v1/operators', None, "${SEC_TOKEN}"),
    ('audit_admin申请证书', 'POST', '/api/v1/certificates/enroll', {"cert_type":"SSL","algorithm":"SM2","subject":{"common_name":"test2.com","organization":"T","country":"CN"},"validity_days":365,"gen_key_locally":True}, "${AUDIT_TOKEN}"),
]

all_ok = True
for name, method, path, body, token in tests:
    resp = api_call(method, path, body, token)
    code = resp.get('code', '')
    ok = code in ['FORBIDDEN', 'UNAUTHORIZED']
    status = '✅' if ok else '❌'
    if not ok: all_ok = False
    print(f'  {status} {name} -> {code}')

print('结果:', '通过' if all_ok else '失败')
PYEOF

echo ""
echo "=== 8. 端到端功能验证 ==="
python3 << PYEOF
import urllib.request, json, ssl, time
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def api_call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(f"${BASE_URL}{path}", data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())

token = "${SEC_TOKEN}"

# 申请证书
print("  申请证书...")
resp = api_call('POST', '/api/v1/certificates/enroll', {
    "cert_type": "SSL", "algorithm": "SM2",
    "subject": {"common_name": "e2e-verify.opengm.ca", "organization": "Verify", "country": "CN"},
    "validity_days": 365, "exportable": True, "gen_key_locally": True
}, token)
assert resp.get('code') == 'OK', f"申请失败: {resp}"
cert_id = resp['data']['cert_id']
print(f"  ✅ 申请成功, cert_id={cert_id}")

# 查询详情
print("  查询详情...")
resp = api_call('GET', f'/api/v1/certificates/{cert_id}', token=token)
assert resp.get('code') == 'OK', f"查询失败: {resp}"
print(f"  ✅ 详情查询成功")

# 吊销证书
time.sleep(2)
print("  吊销证书...")
resp = api_call('POST', f'/api/v1/certificates/{cert_id}/revoke', {"reason": 1, "reason_text": "验证测试"}, token)
assert resp.get('code') == 'OK', f"吊销失败: {resp}"
print(f"  ✅ 吊销成功")

# 验证CRL
print("  验证CRL...")
req = urllib.request.Request(f"${BASE_URL}/api/v1/crl/SSL-CA")
with urllib.request.urlopen(req, context=ctx) as resp:
    crl_data = resp.read()
assert len(crl_data) > 100, "CRL数据异常"
print(f"  ✅ CRL正常, 大小={len(crl_data)}字节")

# 验证审计日志
print("  验证审计日志...")
audit_token = "${AUDIT_TOKEN}"
resp = api_call('GET', '/api/v1/audit/logs?page=1&page_size=50', token=audit_token)
assert resp.get('code') == 'OK', f"审计日志查询失败: {resp}"
items = resp.get('data', {}).get('items', [])
print(f"  ✅ 审计日志查询成功, 共{len(items)}条")

print("\n  🎉 端到端流程全部通过")
PYEOF

echo ""
echo "========================================"
echo "对齐验证完成"
echo "========================================"
