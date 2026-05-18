#!/bin/bash
# openGM-CA 前后端功能对齐测试脚本
set +e

BASE_URL="https://localhost:8443"
TEST_REPORT="/root/opengm-ca/frontend_backend_alignment_report_$(date +%Y%m%d_%H%M%S).md"
PASS=0
FAIL=0
WARN=0

log_info() { echo -e "\033[1;33m[INFO]\033[0m $1"; }
log_pass() { echo -e "\033[0;32m[PASS]\033[0m $1"; }
log_fail() { echo -e "\033[0;31m[FAIL]\033[0m $1"; }
log_warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }

cat > "$TEST_REPORT" << 'EOF'
# openGM-CA 前后端功能对齐测试报告

**测试目标**: 验证前端调用的API与后端实现完全对齐，所有已开发功能都能实现
**测试环境**: https://localhost:8443

EOF

SYS_TOKEN=""
SEC_TOKEN=""
AUDIT_TOKEN=""

get_tokens() {
    SEC_TOKEN=$(curl -sk -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"sec_admin","password":"WOai@8680186"}' | grep -oP '"access_token":"\K[^"]+')
    SYS_TOKEN=$(curl -sk -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"sys_admin","password":"WOai@8680186"}' | grep -oP '"access_token":"\K[^"]+')
    AUDIT_TOKEN=$(curl -sk -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"audit_admin","password":"AuditAdmin@2026"}' | grep -oP '"access_token":"\K[^"]+')
}

test_frontend_basic() {
    log_info "=== 一、前端页面加载与基础功能 ==="
    echo -e "\n## 一、前端页面加载与基础功能" >> "$TEST_REPORT"
    resp=$(curl -sk "${BASE_URL}/")
    if echo "$resp" | grep -q "openGM-CA"; then
        log_pass "前端首页加载成功"
        ((PASS++))
        echo "- ✅ 前端首页 / - 可正常加载" >> "$TEST_REPORT"
    else
        log_fail "前端首页加载失败"
        ((FAIL++))
        echo "- ❌ 前端首页 / - 加载失败" >> "$TEST_REPORT"
    fi
    if echo "$resp" | grep -q "doLogin"; then
        log_pass "前端JS功能代码完整"
        ((PASS++))
        echo "- ✅ 前端JS - 功能代码完整" >> "$TEST_REPORT"
    else
        log_fail "前端JS功能代码缺失"
        ((FAIL++))
        echo "- ❌ 前端JS - 功能代码缺失" >> "$TEST_REPORT"
    fi
    pages="dashboard caChain certificates enroll audit operators hsm config exportApprovals profile"
    all_present=true
    for page in $pages; do
        if ! echo "$resp" | grep -q "page-$page"; then
            all_present=false
            log_fail "前端缺少页面: $page"
            ((FAIL++))
            echo "- ❌ 前端页面 - 缺少 $page" >> "$TEST_REPORT"
        fi
    done
    if $all_present; then
        log_pass "前端包含所有功能页面"
        ((PASS++))
        echo "- ✅ 前端页面 - 所有功能页面完整" >> "$TEST_REPORT"
    fi
    if echo "$resp" | grep -q "sec-admin-only"; then
        log_pass "前端权限控制CSS类存在"
        ((PASS++))
        echo "- ✅ 前端权限 - CSS权限控制类存在" >> "$TEST_REPORT"
    else
        log_fail "前端权限控制CSS类缺失"
        ((FAIL++))
        echo "- ❌ 前端权限 - CSS权限控制类缺失" >> "$TEST_REPORT"
    fi
}

test_auth_alignment() {
    log_info "=== 二、认证模块对齐测试 ==="
    echo -e "\n## 二、认证模块对齐测试" >> "$TEST_REPORT"
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"sec_admin","password":"WOai@8680186"}')
    if echo "$resp" | grep -q '"code":"OK".*"access_token"'; then
        log_pass "登录API返回格式正确"
        ((PASS++))
        echo "- ✅ POST /auth/login - 返回access_token" >> "$TEST_REPORT"
    else
        log_fail "登录API返回格式错误"
        ((FAIL++))
        echo "- ❌ POST /auth/login" >> "$TEST_REPORT"
    fi
    if echo "$resp" | grep -q '"operator".*"role".*"permissions"'; then
        log_pass "登录API返回operator信息"
        ((PASS++))
        echo "- ✅ POST /auth/login - 返回operator(role+permissions)" >> "$TEST_REPORT"
    else
        log_fail "登录API未返回operator信息"
        ((FAIL++))
        echo "- ❌ POST /auth/login - 缺少operator信息" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/auth/refresh" -H "Content-Type: application/json" -d '{"refresh_token":"test"}')
    if [ -n "$resp" ]; then
        log_warn "Token刷新API存在，但前端未实现自动刷新"
        ((WARN++))
        echo "- ⚠️ POST /auth/refresh - 后端已实现，前端未调用" >> "$TEST_REPORT"
    fi
    if [ -n "$SYS_TOKEN" ]; then
        resp=$(curl -sk -X POST "${BASE_URL}/api/v1/auth/init-admins" -H "Authorization: Bearer ${SYS_TOKEN}" -H "Content-Type: application/json" -d '{}')
        if [ -n "$resp" ]; then
            log_warn "初始化管理员API存在，但前端无此页面"
            ((WARN++))
            echo "- ⚠️ POST /auth/init-admins - 后端已实现，前端未调用" >> "$TEST_REPORT"
        fi
    fi
}

test_dashboard_alignment() {
    log_info "=== 三、仪表盘与系统状态对齐测试 ==="
    echo -e "\n## 三、仪表盘与系统状态对齐测试" >> "$TEST_REPORT"
    resp=$(curl -sk "${BASE_URL}/health")
    if echo "$resp" | grep -q '"status":"healthy".*"stats".*"active_certificates"'; then
        log_pass "/health 返回格式正确"
        ((PASS++))
        echo "- ✅ GET /health - 返回stats.active_certificates等" >> "$TEST_REPORT"
    else
        log_fail "/health 返回格式不正确"
        ((FAIL++))
        echo "- ❌ GET /health" >> "$TEST_REPORT"
    fi
    if [ -n "$SYS_TOKEN" ]; then
        resp=$(curl -sk "${BASE_URL}/api/v1/system/status" -H "Authorization: Bearer ${SYS_TOKEN}")
        if echo "$resp" | grep -q '"code":"OK"'; then
            log_pass "/system/status 可访问"
            ((PASS++))
            echo "- ✅ GET /system/status - 可访问" >> "$TEST_REPORT"
        else
            log_fail "/system/status 访问失败"
            ((FAIL++))
            echo "- ❌ GET /system/status" >> "$TEST_REPORT"
        fi
        resp=$(curl -sk "${BASE_URL}/api/v1/system/expiring-certs" -H "Authorization: Bearer ${SYS_TOKEN}")
        if echo "$resp" | grep -q '"code":"OK"'; then
            log_warn "即将过期证书API存在，前端仪表盘未调用"
            ((WARN++))
            echo "- ⚠️ GET /system/expiring-certs - 后端已实现，前端未调用" >> "$TEST_REPORT"
        fi
    fi
}

test_cachain_alignment() {
    log_info "=== 四、CA证书链对齐测试 ==="
    echo -e "\n## 四、CA证书链对齐测试" >> "$TEST_REPORT"
    resp=$(curl -sk "${BASE_URL}/api/v1/ca/chain")
    if echo "$resp" | grep -q '"code":"OK".*"data".*"cert_pem"'; then
        log_pass "CA证书链API返回格式正确"
        ((PASS++))
        echo "- ✅ GET /api/v1/ca/chain - 返回cert_pem等字段" >> "$TEST_REPORT"
    else
        log_fail "CA证书链API返回格式错误"
        ((FAIL++))
        echo "- ❌ GET /api/v1/ca/chain" >> "$TEST_REPORT"
    fi
    fields_ok=true
    for field in ca_name ca_type algorithm serial_number valid_to cert_pem; do
        if ! echo "$resp" | grep -q "\"$field\""; then
            fields_ok=false
            log_fail "CA证书链缺少字段: $field"
            ((FAIL++))
            echo "- ❌ GET /api/v1/ca/chain - 缺少字段 $field" >> "$TEST_REPORT"
        fi
    done
    if $fields_ok; then
        log_pass "CA证书链包含所有前端所需字段"
        ((PASS++))
        echo "- ✅ GET /api/v1/ca/chain - 字段完整" >> "$TEST_REPORT"
    fi
}

test_cert_alignment() {
    log_info "=== 五、证书管理对齐测试 ==="
    echo -e "\n## 五、证书管理对齐测试" >> "$TEST_REPORT"
    if [ -z "$SEC_TOKEN" ]; then
        log_fail "SEC_TOKEN为空"
        echo "- ⚠️ 跳过 - Token未获取" >> "$TEST_REPORT"
        return
    fi
    log_info "测试证书列表查询参数对齐..."
    resp_cn=$(curl -sk "${BASE_URL}/api/v1/certificates?cn=e2e-test.opengm.ca" -H "Authorization: Bearer ${SEC_TOKEN}")
    count_cn=$(echo "$resp_cn" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('data',{}).get('items',[])))" 2>/dev/null || echo "0")
    resp_subject_cn=$(curl -sk "${BASE_URL}/api/v1/certificates?subject_cn=e2e-test.opengm.ca" -H "Authorization: Bearer ${SEC_TOKEN}")
    count_subject_cn=$(echo "$resp_subject_cn" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('data',{}).get('items',[])))" 2>/dev/null || echo "0")
    if [ "$count_cn" != "$count_subject_cn" ]; then
        log_fail "证书列表查询参数不对齐: 前端用'cn'，后端用'subject_cn'"
        ((FAIL++))
        echo "- ❌ GET /certificates - 参数不对齐: 前端用'cn'，后端用'subject_cn'" >> "$TEST_REPORT"
        echo "  - cn=e2e-test.opengm.ca 返回 $count_cn 条" >> "$TEST_REPORT"
        echo "  - subject_cn=e2e-test.opengm.ca 返回 $count_subject_cn 条" >> "$TEST_REPORT"
    else
        log_pass "证书列表查询参数对齐"
        ((PASS++))
        echo "- ✅ GET /certificates - 查询参数对齐" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/certificates" -H "Authorization: Bearer ${SEC_TOKEN}")
    if echo "$resp" | grep -q '"total".*"page".*"page_size".*"items"'; then
        log_pass "证书列表分页格式正确"
        ((PASS++))
        echo "- ✅ GET /certificates - 分页格式正确(total/page/page_size/items)" >> "$TEST_REPORT"
    else
        log_fail "证书列表分页格式错误"
        ((FAIL++))
        echo "- ❌ GET /certificates - 分页格式错误" >> "$TEST_REPORT"
    fi
    required_fields="id cert_type subject_dn serial_number status valid_from valid_to cert_pem key_id"
    all_fields=true
    for field in $required_fields; do
        if ! echo "$resp" | grep -q "\"$field\""; then
            all_fields=false
            log_warn "证书列表可能缺少字段: $field"
            echo "- ⚠️ GET /certificates - 可能缺少字段 $field" >> "$TEST_REPORT"
        fi
    done
    if $all_fields; then
        log_pass "证书列表包含前端所需字段"
        ((PASS++))
        echo "- ✅ GET /certificates - 字段完整" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/certificates/enroll" -H "Authorization: Bearer ${SEC_TOKEN}" -H "Content-Type: application/json" -d '{"cert_type":"SSL","algorithm":"SM2","subject":{"common_name":"align-test.opengm.ca","organization":"AlignTest","country":"CN"},"validity_days":365,"exportable":true,"gen_key_locally":true}')
    if echo "$resp" | grep -q '"code":"OK".*"cert_id".*"private_key_pem"'; then
        log_pass "证书申请(本地生成)返回格式正确"
        ((PASS++))
        echo "- ✅ POST /certificates/enroll - 返回cert_id和private_key_pem" >> "$TEST_REPORT"
        ALIGN_CERT_ID=$(echo "$resp" | grep -oP '"cert_id":"\K[^"]+' | head -1)
    else
        log_fail "证书申请(本地生成)返回格式错误"
        ((FAIL++))
        echo "- ❌ POST /certificates/enroll - 返回格式错误" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/certificates/enroll" -H "Authorization: Bearer ${SEC_TOKEN}" -H "Content-Type: application/json" -d '{"cert_type":"SSL","algorithm":"SM2","subject":{"common_name":"san-align.opengm.ca","organization":"Test","country":"CN"},"validity_days":365,"exportable":false,"gen_key_locally":true,"extensions":{"subject_alt_names":[{"type":"dns","value":"www.san-align.opengm.ca"}]}}')
    if echo "$resp" | grep -q '"code":"OK"'; then
        log_pass "证书申请(SANs扩展)成功"
        ((PASS++))
        echo "- ✅ POST /certificates/enroll - SANs扩展支持正常" >> "$TEST_REPORT"
    else
        log_fail "证书申请(SANs扩展)失败"
        ((FAIL++))
        echo "- ❌ POST /certificates/enroll - SANs扩展失败" >> "$TEST_REPORT"
    fi
    if [ -n "$ALIGN_CERT_ID" ]; then
        sleep 2
        resp=$(curl -sk -X POST "${BASE_URL}/api/v1/certificates/${ALIGN_CERT_ID}/revoke" -H "Authorization: Bearer ${SEC_TOKEN}" -H "Content-Type: application/json" -d '{"reason":0,"reason_text":"对齐测试吊销"}')
        if echo "$resp" | grep -q '"code":"OK"'; then
            log_pass "证书吊销API字段对齐"
            ((PASS++))
            echo "- ✅ POST /certificates/:id/revoke - 字段对齐(reason+reason_text)" >> "$TEST_REPORT"
        else
            log_fail "证书吊销API字段不对齐"
            ((FAIL++))
            echo "- ❌ POST /certificates/:id/revoke - 响应异常" >> "$TEST_REPORT"
        fi
        resp=$(curl -sk -X POST "${BASE_URL}/api/v1/certificates/${ALIGN_CERT_ID}/renew" -H "Authorization: Bearer ${SEC_TOKEN}" -H "Content-Type: application/json" -d '{"validity_days":365}')
        if echo "$resp" | grep -q '"code":"NOT_IMPLEMENTED"'; then
            log_warn "证书续期API返回NOT_IMPLEMENTED，前端也无续期按钮"
            ((WARN++))
            echo "- ⚠️ POST /certificates/:id/renew - 后端返回NOT_IMPLEMENTED，前端未实现" >> "$TEST_REPORT"
        fi
    fi
    CERT_ID=$(curl -sk "${BASE_URL}/api/v1/certificates" -H "Authorization: Bearer ${SEC_TOKEN}" | grep -oP '"id":\K[0-9]+' | head -1)
    if [ -n "$CERT_ID" ]; then
        resp=$(curl -sk "${BASE_URL}/api/v1/certificates/${CERT_ID}" -H "Authorization: Bearer ${SEC_TOKEN}")
        if echo "$resp" | grep -q '"code":"OK"'; then
            log_pass "证书详情API存在且可访问"
            ((PASS++))
            echo "- ✅ GET /certificates/:id - API存在且正常" >> "$TEST_REPORT"
        else
            log_fail "证书详情API访问失败"
            ((FAIL++))
            echo "- ❌ GET /certificates/:id" >> "$TEST_REPORT"
        fi
    fi
}

test_key_alignment() {
    log_info "=== 六、密钥管理对齐测试 ==="
    echo -e "\n## 六、密钥管理对齐测试" >> "$TEST_REPORT"
    if [ -z "$SEC_TOKEN" ]; then
        log_fail "SEC_TOKEN为空"
        echo "- ⚠️ 跳过 - Token未获取" >> "$TEST_REPORT"
        return
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/keys" -H "Authorization: Bearer ${SEC_TOKEN}")
    if echo "$resp" | grep -q '"message":"密钥列表功能开发中"'; then
        log_warn "密钥列表API返回'功能开发中'"
        ((WARN++))
        echo "- ⚠️ GET /keys - 后端返回'功能开发中'，前端密钥列表将无法显示" >> "$TEST_REPORT"
    elif echo "$resp" | grep -q '"code":"OK"'; then
        log_pass "密钥列表API正常"
        ((PASS++))
        echo "- ✅ GET /keys - API正常" >> "$TEST_REPORT"
    else
        log_fail "密钥列表API异常"
        ((FAIL++))
        echo "- ❌ GET /keys - 异常响应" >> "$TEST_REPORT"
    fi
    KEY_ID=$(curl -sk "${BASE_URL}/api/v1/keys" -H "Authorization: Bearer ${SEC_TOKEN}" | grep -oP '"id":\K[0-9]+' | head -1)
    if [ -n "$KEY_ID" ]; then
        resp=$(curl -sk -X POST "${BASE_URL}/api/v1/keys/${KEY_ID}/export-request" -H "Authorization: Bearer ${SEC_TOKEN}" -H "Content-Type: application/json" -d '{"reason":"对齐测试导出申请","password":"Export@2026!!"}')
        if echo "$resp" | grep -q '"code":"OK"'; then
            log_pass "密钥导出申请API正常"
            ((PASS++))
            echo "- ✅ POST /keys/:id/export-request - API正常" >> "$TEST_REPORT"
        else
            log_fail "密钥导出申请API异常"
            ((FAIL++))
            echo "- ❌ POST /keys/:id/export-request" >> "$TEST_REPORT"
        fi
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/keys/export-requests?page=1&page_size=10" -H "Authorization: Bearer ${SEC_TOKEN}")
    if echo "$resp" | grep -q '"code":"OK".*"items"'; then
        log_pass "导出申请列表API返回格式正确"
        ((PASS++))
        echo "- ✅ GET /keys/export-requests - 分页格式正确" >> "$TEST_REPORT"
    else
        log_fail "导出申请列表API返回格式错误"
        ((FAIL++))
        echo "- ❌ GET /keys/export-requests" >> "$TEST_REPORT"
    fi
    required_fields="request_id key_id requester reason status created_at expires_at"
    all_fields=true
    for field in $required_fields; do
        if ! echo "$resp" | grep -q "\"$field\""; then
            all_fields=false
            log_warn "导出申请列表可能缺少字段: $field"
            echo "- ⚠️ GET /keys/export-requests - 可能缺少字段 $field" >> "$TEST_REPORT"
        fi
    done
    if $all_fields; then
        log_pass "导出申请列表字段完整"
        ((PASS++))
        echo "- ✅ GET /keys/export-requests - 字段完整" >> "$TEST_REPORT"
    fi
}

test_hsm_alignment() {
    log_info "=== 七、HSM管理对齐测试 ==="
    echo -e "\n## 七、HSM管理对齐测试" >> "$TEST_REPORT"
    if [ -z "$SEC_TOKEN" ]; then
        log_fail "SEC_TOKEN为空"
        echo "- ⚠️ 跳过 - Token未获取" >> "$TEST_REPORT"
        return
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/hsm/status" -H "Authorization: Bearer ${SEC_TOKEN}")
    if echo "$resp" | grep -q '"code":"OK"'; then
        log_pass "HSM状态API正常"
        ((PASS++))
        echo "- ✅ GET /hsm/status - API正常" >> "$TEST_REPORT"
        if echo "$resp" | grep -q '"type".*"key_count".*"storage_path"'; then
            log_pass "HSM状态包含前端所需字段"
            ((PASS++))
            echo "- ✅ GET /hsm/status - 字段完整(type/key_count/storage_path)" >> "$TEST_REPORT"
        else
            log_warn "HSM状态可能缺少前端字段"
            ((WARN++))
            echo "- ⚠️ GET /hsm/status - 可能缺少前端字段" >> "$TEST_REPORT"
        fi
    else
        log_fail "HSM状态API异常"
        ((FAIL++))
        echo "- ❌ GET /hsm/status" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/hsm/keys" -H "Authorization: Bearer ${SEC_TOKEN}")
    if echo "$resp" | grep -q '"code":"OK"'; then
        log_pass "HSM密钥列表API正常"
        ((PASS++))
        echo "- ✅ GET /hsm/keys - API正常" >> "$TEST_REPORT"
        if echo "$resp" | grep -q '"handle".*"algorithm".*"key_type".*"created_at"'; then
            log_pass "HSM密钥列表包含前端所需字段"
            ((PASS++))
            echo "- ✅ GET /hsm/keys - 字段完整(handle/algorithm/key_type/created_at)" >> "$TEST_REPORT"
        else
            log_warn "HSM密钥列表可能缺少前端字段"
            ((WARN++))
            echo "- ⚠️ GET /hsm/keys - 可能缺少前端字段" >> "$TEST_REPORT"
        fi
    else
        log_fail "HSM密钥列表API异常"
        ((FAIL++))
        echo "- ❌ GET /hsm/keys" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/hsm/keys" -H "Authorization: Bearer ${SEC_TOKEN}" -H "Content-Type: application/json" -d '{"algorithm":"SM2","key_type":"SIGN"}')
    if echo "$resp" | grep -q '"code":"OK"'; then
        log_pass "HSM生成密钥API字段对齐"
        ((PASS++))
        echo "- ✅ POST /hsm/keys - 字段对齐(algorithm+key_type)" >> "$TEST_REPORT"
        HSM_HANDLE=$(echo "$resp" | grep -oP '"handle":"\K[^"]+' | head -1)
        if [ -n "$HSM_HANDLE" ]; then
            curl -sk -X DELETE "${BASE_URL}/api/v1/hsm/keys/${HSM_HANDLE}" -H "Authorization: Bearer ${SEC_TOKEN}" >/dev/null 2>&1
        fi
    else
        log_fail "HSM生成密钥API字段不对齐"
        ((FAIL++))
        echo "- ❌ POST /hsm/keys - 响应异常" >> "$TEST_REPORT"
    fi
}

test_audit_alignment() {
    log_info "=== 八、审计日志对齐测试 ==="
    echo -e "\n## 八、审计日志对齐测试" >> "$TEST_REPORT"
    if [ -z "$AUDIT_TOKEN" ]; then
        log_fail "AUDIT_TOKEN为空"
        echo "- ⚠️ 跳过 - Token未获取" >> "$TEST_REPORT"
        return
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/audit/logs?page=1&page_size=15" -H "Authorization: Bearer ${AUDIT_TOKEN}")
    if echo "$resp" | grep -q '"code":"OK".*"items"'; then
        log_pass "审计日志列表API格式正确"
        ((PASS++))
        echo "- ✅ GET /audit/logs - 分页格式正确" >> "$TEST_REPORT"
    else
        log_fail "审计日志列表API格式错误"
        ((FAIL++))
        echo "- ❌ GET /audit/logs" >> "$TEST_REPORT"
    fi
    required_fields="event_time event_type severity actor action result"
    all_fields=true
    for field in $required_fields; do
        if ! echo "$resp" | grep -q "\"$field\""; then
            all_fields=false
            log_warn "审计日志可能缺少字段: $field"
            echo "- ⚠️ GET /audit/logs - 可能缺少字段 $field" >> "$TEST_REPORT"
        fi
    done
    if $all_fields; then
        log_pass "审计日志字段完整"
        ((PASS++))
        echo "- ✅ GET /audit/logs - 字段完整" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/audit/verify" -H "Authorization: Bearer ${AUDIT_TOKEN}")
    if echo "$resp" | grep -q '"code":"OK"'; then
        log_warn "审计日志校验API存在，前端未提供校验按钮"
        ((WARN++))
        echo "- ⚠️ GET /audit/verify - 后端已实现，前端未调用" >> "$TEST_REPORT"
    fi
}

test_operator_alignment() {
    log_info "=== 九、操作员管理对齐测试 ==="
    echo -e "\n## 九、操作员管理对齐测试" >> "$TEST_REPORT"
    if [ -z "$SYS_TOKEN" ]; then
        log_fail "SYS_TOKEN为空"
        echo "- ⚠️ 跳过 - Token未获取" >> "$TEST_REPORT"
        return
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/operators" -H "Authorization: Bearer ${SYS_TOKEN}")
    if echo "$resp" | grep -q '"code":"OK"'; then
        log_pass "操作员列表API正常"
        ((PASS++))
        echo "- ✅ GET /operators - API正常" >> "$TEST_REPORT"
    else
        log_fail "操作员列表API异常"
        ((FAIL++))
        echo "- ❌ GET /operators" >> "$TEST_REPORT"
    fi
    required_fields="id username real_name role email is_active last_login_at"
    all_fields=true
    for field in $required_fields; do
        if ! echo "$resp" | grep -q "\"$field\""; then
            all_fields=false
            log_warn "操作员列表可能缺少字段: $field"
            echo "- ⚠️ GET /operators - 可能缺少字段 $field" >> "$TEST_REPORT"
        fi
    done
    if $all_fields; then
        log_pass "操作员列表字段完整"
        ((PASS++))
        echo "- ✅ GET /operators - 字段完整" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/operators" -H "Authorization: Bearer ${SYS_TOKEN}" -H "Content-Type: application/json" -d '{"username":"align_test_user","password":"TestPass123456!","real_name":"对齐测试","email":"align@test.com","phone":"13800138000","role":"SYS_ADMIN"}')
    if echo "$resp" | grep -q '"code":"OK"'; then
        log_pass "创建操作员API字段对齐"
        ((PASS++))
        echo "- ✅ POST /operators - 字段对齐(username/password/real_name/email/phone/role)" >> "$TEST_REPORT"
        ALIGN_OP_ID=$(echo "$resp" | grep -oP '"id":\K[0-9]+' | head -1)
    else
        log_fail "创建操作员API字段不对齐"
        ((FAIL++))
        echo "- ❌ POST /operators" >> "$TEST_REPORT"
    fi
    if [ -n "$ALIGN_OP_ID" ]; then
        resp=$(curl -sk -X POST "${BASE_URL}/api/v1/operators/${ALIGN_OP_ID}/status" -H "Authorization: Bearer ${SYS_TOKEN}" -H "Content-Type: application/json" -d '{"is_active":false}')
        if echo "$resp" | grep -q '"code":"OK"'; then
            log_pass "操作员状态切换API字段对齐"
            ((PASS++))
            echo "- ✅ POST /operators/:id/status - 字段对齐(is_active)" >> "$TEST_REPORT"
        else
            log_fail "操作员状态切换API字段不对齐"
            ((FAIL++))
            echo "- ❌ POST /operators/:id/status" >> "$TEST_REPORT"
        fi
        resp=$(curl -sk -X DELETE "${BASE_URL}/api/v1/operators/${ALIGN_OP_ID}" -H "Authorization: Bearer ${SYS_TOKEN}")
        if echo "$resp" | grep -q '"code":"OK"'; then
            log_pass "删除操作员API正常"
            ((PASS++))
            echo "- ✅ DELETE /operators/:id - API正常" >> "$TEST_REPORT"
        else
            log_fail "删除操作员API异常"
            ((FAIL++))
            echo "- ❌ DELETE /operators/:id" >> "$TEST_REPORT"
        fi
    fi
    resp=$(curl -sk -X PUT "${BASE_URL}/api/v1/operators/4" -H "Authorization: Bearer ${SYS_TOKEN}" -H "Content-Type: application/json" -d '{"real_name":"测试修改"}')
    if [ -n "$resp" ]; then
        log_warn "操作员更新API存在，前端无编辑功能"
        ((WARN++))
        echo "- ⚠️ PUT /operators/:id - 后端已实现，前端未调用" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/operators/4/password" -H "Authorization: Bearer ${SYS_TOKEN}" -H "Content-Type: application/json" -d '{"old_password":"WOai@8680186","new_password":"NewPass@12345678!"}')
    if echo "$resp" | grep -q '"code":"OK"'; then
        log_pass "修改密码API字段对齐"
        ((PASS++))
        echo "- ✅ POST /operators/:id/password - 字段对齐(old_password+new_password)" >> "$TEST_REPORT"
        curl -sk -X POST "${BASE_URL}/api/v1/operators/4/password" -H "Authorization: Bearer ${SYS_TOKEN}" -H "Content-Type: application/json" -d '{"old_password":"NewPass@12345678!","new_password":"WOai@8680186"}' >/dev/null 2>&1
    else
        log_fail "修改密码API字段不对齐"
        ((FAIL++))
        echo "- ❌ POST /operators/:id/password" >> "$TEST_REPORT"
    fi
}

test_public_alignment() {
    log_info "=== 十、公开接口对齐测试 ==="
    echo -e "\n## 十、公开接口对齐测试" >> "$TEST_REPORT"
    resp=$(curl -sk "${BASE_URL}/api/v1/crl/SSL-CA")
    if [ -n "$resp" ] && [ "${#resp}" -gt 100 ]; then
        log_pass "CRL接口返回DER数据"
        ((PASS++))
        echo "- ✅ GET /crl/:ca_name - 返回DER格式数据" >> "$TEST_REPORT"
    else
        log_fail "CRL接口异常"
        ((FAIL++))
        echo "- ❌ GET /crl/:ca_name" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/ocsp" -H "Content-Type: application/ocsp-request" -d "test")
    if [ -n "$resp" ]; then
        log_pass "OCSP接口可达"
        ((PASS++))
        echo "- ✅ POST /ocsp - 接口可达" >> "$TEST_REPORT"
    else
        log_fail "OCSP接口异常"
        ((FAIL++))
        echo "- ❌ POST /ocsp" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/metrics")
    if echo "$resp" | grep -q 'go_'; then
        log_pass "Metrics接口返回Prometheus数据"
        ((PASS++))
        echo "- ✅ GET /metrics - Prometheus指标正常" >> "$TEST_REPORT"
    else
        log_fail "Metrics接口异常"
        ((FAIL++))
        echo "- ❌ GET /metrics" >> "$TEST_REPORT"
    fi
}

test_permission_alignment() {
    log_info "=== 十一、权限隔离对齐测试 ==="
    echo -e "\n## 十一、权限隔离对齐测试" >> "$TEST_REPORT"
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/certificates/enroll" -H "Authorization: Bearer ${SYS_TOKEN}" -H "Content-Type: application/json" -d '{"cert_type":"SSL","algorithm":"SM2","subject":{"common_name":"deny.opengm.ca","organization":"Test","country":"CN"},"validity_days":365,"gen_key_locally":true}')
    if echo "$resp" | grep -q '"code":"FORBIDDEN"\|"code":"UNAUTHORIZED"'; then
        log_pass "sys_admin 申请证书被正确拒绝"
        ((PASS++))
        echo "- ✅ 权限隔离 - sys_admin无法申请证书" >> "$TEST_REPORT"
    else
        log_fail "sys_admin 申请证书未被拒绝"
        ((FAIL++))
        echo "- ❌ 权限隔离 - sys_admin可申请证书" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/operators" -H "Authorization: Bearer ${SEC_TOKEN}")
    if echo "$resp" | grep -q '"code":"FORBIDDEN"\|"code":"UNAUTHORIZED"'; then
        log_pass "sec_admin 访问操作员管理被正确拒绝"
        ((PASS++))
        echo "- ✅ 权限隔离 - sec_admin无法访问操作员管理" >> "$TEST_REPORT"
    else
        log_fail "sec_admin 访问操作员管理未被拒绝"
        ((FAIL++))
        echo "- ❌ 权限隔离 - sec_admin可访问操作员管理" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk "${BASE_URL}/api/v1/audit/logs" -H "Authorization: Bearer ${AUDIT_TOKEN}")
    if echo "$resp" | grep -q '"code":"OK"'; then
        log_pass "audit_admin 可访问审计日志"
        ((PASS++))
        echo "- ✅ 权限隔离 - audit_admin可访问审计日志" >> "$TEST_REPORT"
    else
        log_fail "audit_admin 访问审计日志失败"
        ((FAIL++))
        echo "- ❌ 权限隔离 - audit_admin无法访问审计日志" >> "$TEST_REPORT"
    fi
    resp=$(curl -sk -X POST "${BASE_URL}/api/v1/certificates/enroll" -H "Authorization: Bearer ${AUDIT_TOKEN}" -H "Content-Type: application/json" -d '{"cert_type":"SSL","algorithm":"SM2","subject":{"common_name":"deny2.opengm.ca","organization":"Test","country":"CN"},"validity_days":365,"gen_key_locally":true}')
    if echo "$resp" | grep -q '"code":"FORBIDDEN"\|"code":"UNAUTHORIZED"'; then
        log_pass "audit_admin 申请证书被正确拒绝"
        ((PASS++))
        echo "- ✅ 权限隔离 - audit_admin无法申请证书" >> "$TEST_REPORT"
    else
        log_fail "audit_admin 申请证书未被拒绝"
        ((FAIL++))
        echo "- ❌ 权限隔离 - audit_admin可申请证书" >> "$TEST_REPORT"
    fi
}

main() {
    log_info "开始 openGM-CA 前后端功能对齐测试"
    get_tokens
    test_frontend_basic
    test_auth_alignment
    test_dashboard_alignment
    test_cachain_alignment
    test_cert_alignment
    test_key_alignment
    test_hsm_alignment
    test_audit_alignment
    test_operator_alignment
    test_public_alignment
    test_permission_alignment
    TOTAL=$((PASS + FAIL + WARN))
    log_info "========================================"
    log_info "对齐测试完成! 通过: $PASS  | 失败: $FAIL  | 警告: $WARN  | 总计: $TOTAL"
    log_info "========================================"
    cat >> "$TEST_REPORT" << EOF

---

## 十二、测试统计

| 统计项 | 数值 |
|--------|------|
| 通过数 | $PASS |
| 失败数 | $FAIL |
| 警告数 | $WARN |
| 总测试数 | $TOTAL |

**测试结论**: $(if [ "$FAIL" -eq 0 ]; then echo "✅ 无严重对齐问题"; else echo "❌ 存在 $FAIL 项严重对齐问题"; fi)

**已知前后端不对齐项**:
1. ❌ 证书列表查询参数: 前端用 \`cn\`，后端用 \`subject_cn\`
2. ⚠️ 密钥列表: 后端返回"功能开发中"
3. ⚠️ 证书续期: 后端返回 NOT_IMPLEMENTED，前端无续期按钮
4. ⚠️ 操作员编辑: 后端有 PUT /operators/:id，前端无编辑功能
5. ⚠️ 审计日志校验: 后端有 GET /audit/verify，前端无校验按钮
6. ⚠️ Token刷新: 后端有 POST /auth/refresh，前端无自动刷新
7. ⚠️ 即将过期证书: 后端有 GET /system/expiring-certs，前端未调用
8. ⚠️ 初始化管理员: 后端有 POST /auth/init-admins，前端无页面

EOF
    echo ""
    echo "对齐测试报告已保存: $TEST_REPORT"
}

main "$@"
