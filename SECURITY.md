# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in openGM-CA, please report it responsibly:

1. **Do not** open a public issue
2. Send details to the project maintainers via the contact information in `README.md`
3. Allow reasonable time for investigation and patch before public disclosure

## Security Design Principles

openGM-CA is designed with the following security principles:

- **Defense in depth**: Multiple layers of protection (TLS, JWT, RBAC, audit logging, hash chain)
- **Least privilege**: Three-administrator separation (SYS_ADMIN / SEC_ADMIN / AUDITOR) following 等保 2.0
- **Fail secure**: Service refuses to start with weak JWT secrets, refuses to load plaintext private keys
- **Cryptographic agility**: Supports both international (RSA/ECC) and national cryptographic (SM2/SM3/SM4) algorithms
- **Auditability**: All critical operations are logged with hash-chain integrity protection

## Security Hardening Checklist

Before deploying to production, ensure:

- [ ] `CA_JWT_SECRET` is set to a random string with length ≥ 32
- [ ] `CA_MASTER_KEY` is set (required for private key encryption and export)
- [ ] `CA_HSM_PASSWORD` is set (required for soft HSM initialization)
- [ ] `server.tls.enabled` is `true` in `config.yaml`
- [ ] Default administrator passwords are set via `CA_DEFAULT_*_ADMIN_PASSWORD` or securely stored after random generation
- [ ] Database `ssl_mode` is set to `require` or `verify-ca`
- [ ] File permissions on `./data/ca_keys/` are `0600`
- [ ] `key_management.export.requires_approval` is `true`

## Fixed Security Issues

### 2026-05-09 — Second Round Security Hardening

The following high and medium severity issues were fixed in this release:

| Severity | Issue | Fix Location |
|----------|-------|--------------|
| High | Audit hash chain could fork under concurrent load | `internal/service/audit.go` — added `sync.Mutex` |
| High | `/auth/init-admins` was publicly accessible without authentication | `internal/api/router.go` — moved into auth group with `RequirePermission("USER_MANAGE")` |
| High | Random password fallback used `UnixNano()` on entropy failure | `internal/api/handler/auth.go` — now returns error on `rand.Read` failure |
| High | Dual certificate private keys were not persisted after issuance | `internal/core/dual_cert.go` — inject `keyStore`/`keyRepo` and persist keys |
| High | Plaintext private keys could be silently loaded from disk | `internal/core/ca.go` — `decryptKeyFile` rejects unencrypted files |
| High | SM2 `SignDigest` performed double hashing | `internal/core/signer.go` — use `autoHash=false` |
| High | Certificate validity could exceed CA validity | `internal/service/enrollment.go` — truncate `notAfter` to `ca.ValidTo` |
| High | CRL was not regenerated immediately after revocation | `internal/service/management.go` — call `generateAndSaveCRL` after revoke |
| High | Key export count had race condition | `internal/repository/key_repo.go` — atomic `UPDATE ... WHERE export_count < max_exports` |
| Medium | Default admin password was hardcoded | `cmd/ca-server/main.go`, `internal/api/handler/auth.go` — env variable or random bcrypt |
| Medium | `json.Marshal` errors in audit were silently ignored | `internal/model/audit.go` — unified `toMap()` with panic on failure |
| Medium | Invalid cert types were silently downgraded | `internal/service/enrollment.go` — return error for unknown types |
| Medium | Password reset did not enforce strength policy | `internal/api/handler/operator.go` — add `validatePasswordStrength` |
| Medium | Operator role updates had no validation | `internal/model/operator.go`, `internal/api/handler/operator.go` — add `IsValidRole` |
| Medium | JWT `sub` claim was not type-asserted | `internal/api/middleware/auth.go` — force `.(string)` assertion |

### 2026-05-09 — Third Round Security Hardening

| Severity | Issue | Fix Location |
|----------|-------|--------------|
| Critical | Audit channel closed-send panic | `internal/service/audit.go` — `atomic.Bool closed` + `recover()` |
| Critical | Audit hash chain still forked under concurrency | `internal/service/audit.go` — in-memory `lastHash` instead of DB query |
| Critical | OCSP response used wrong issuer certificate | `internal/api/handler/ocsp.go` — `ocsp.CreateResponse(caCert, responderCert, ...)` |
| Critical | CRL generation failure did not block revocation | `internal/service/management.go` — rollback cert status on CRL failure |
| Critical | Subject GetOrCreate TOCTOU race condition | `internal/repository/subject_repo.go` — `RunInTx` with SELECT + INSERT |
| High | Rate limiter memory leak (OOM) | `internal/api/middleware/auth.go` — periodic expired entry cleanup |
| High | JWT middleware did not check user real-time status | `internal/api/middleware/auth.go` — `UserStatusChecker` callback |
| High | Login fail lock had race condition | `internal/repository/operator_repo.go` — `RETURNING login_fail_count` |
| High | OperatorRepository.Update overwrote all fields | `internal/repository/operator_repo.go` — `Column` whitelist: `UpdateProfile/UpdatePassword/ToggleStatus` |
| High | User self password change skipped strength check | `internal/api/handler/operator.go` — add `validatePasswordStrength` |
| High | HSM GCM ciphertext format non-standard | `internal/hsm/softhsm.go` — `gcm.Seal(nil, nonce, plaintext, nil)` |
| High | Key export approval logic inverted | `internal/service/key_export.go` — check `ExportApprovers >= ApprovalLevels` |
| Medium | PBKDF2 iterations too low (10,000 / 100,000) | `internal/hsm/softhsm.go` (600,000), `internal/service/key_export.go` (600,000) |
| Medium | Certificate `NotBefore` lacked clock skew tolerance | `internal/core/ca.go` — `time.Now().Add(-1 * time.Hour)` |
| Medium | CRL `NextUpdate` hardcoded, 10,000 entry limit | `internal/api/handler/crl.go`, `internal/service/management.go` — use config, no limit |
| Medium | Key-Cert association not persisted | `internal/service/enrollment.go`, `internal/repository/key_repo.go` — `UpdateCertID` |
| Medium | Dual cert pair IDs were zero (not persisted) | `internal/core/dual_cert.go`, `internal/repository/cert_repo.go` — persist then set pair ID |
| Low | Missing security response headers | `cmd/ca-server/main.go` — HSTS, X-Frame-Options, etc. |
| Low | HSM delete key did not secure erase | `internal/hsm/softhsm.go` — zero-fill `EncryptedKey` before delete |
| Low | HSM load errors silently ignored | `internal/hsm/softhsm.go` — structured warn logs on load failure |
| Low | GenerateKeyID fell back to random on error | `internal/core/ca.go` — return zero slice instead of random |
| Low | Master key did not support hex/base64 | `internal/crypto/keystore.go` — auto-detect hex(64) and base64 |
| Low | Certificate scheduler lacked panic recover | `internal/service/scheduler.go` — `defer recover()` per scan tick |

### 2026-05-09 — Fourth Round Security Hardening

| Severity | Issue | Fix Location |
|----------|-------|--------------|
| High | JWT secret length not validated | `internal/api/middleware/auth.go`, `internal/config/config.go` — enforce ≥32 bytes |
| High | Master key base64 decode ambiguity | `internal/crypto/keystore.go` — prioritize hex, validate decoded length |
| Medium | Export password only checked length | `internal/service/key_export.go` — require uppercase+lowercase+number+special (12+ chars) |
| Medium | SM2 private key encoding inconsistent | `internal/core/ca.go` — reuse crypto package functions |

### 2026-05-17 — Fifth Round Security Hardening

The following high and medium severity issues were fixed based on comprehensive security audit:

| Severity | Issue | Fix Location |
|----------|-------|--------------|
| High | Master key source validation insufficient | `internal/crypto/keystore.go` — file permission check (≤0600), symlink detection, source type logging |
| High | API input parameter size not limited | `internal/api/middleware/request_limit.go`, `internal/api/handler/certificate.go` — request body size limits, field length validation |
| Medium | HSM PBKDF2 iterations inconsistent | `internal/hsm/softhsm.go` — unified to 600,000 iterations for both master key and KEK derivation |
| Medium | Database DSN could leak in logs | `internal/repository/db.go` — use redacted DSN in error messages and logs |
| Medium | Audit queue full could block requests | `internal/service/audit.go` — increased queue capacity to 5000, added backup file mechanism |

**Key improvements:**
- Master key file permission validation prevents unauthorized access
- API request size limits prevent DoS attacks via large payloads
- Unified PBKDF2 iterations (600,000) meet OWASP recommendations
- Database password redaction prevents credential leakage in logs
- Audit queue backup mechanism prevents service blocking under high load

## Cryptographic Details

### Private Key Encryption

CA private keys and escrowed end-entity keys are encrypted using:
- **Algorithm**: SM4-GCM (national crypto) or AES-256-GCM (international)
- **Key Derivation**: HKDF-SHA256 from `CA_MASTER_KEY`
- **Storage Format**: JSON wrapper (`{"encrypted":true,"ciphertext":"...","salt":"...","nonce":"...","tag":"..."}`)
- **Plaintext PEM rejection**: The loader explicitly rejects any file without the encrypted JSON wrapper

### Key Export Encryption

Exported private keys are encrypted with a user-provided password:
- **KDF**: PBKDF2-HMAC-SHA256, **600,000** iterations (upgraded from 100,000)
- **Algorithm**: AES-256-GCM
- **Format**: PKCS#8 (universal) or algorithm-specific (SM2/RSA/EC)
- **Password policy**: Minimum 12 characters enforced at export time

### Audit Hash Chain

Each audit log entry includes:
- `prev_hash`: SHA-256 of the previous entry's `curr_hash`
- `curr_hash`: SHA-256(`prev_hash` + SHA-256(record_content))
- **Concurrency protection**: In-memory `lastHash` with `sync.Mutex` serializes hash chain computation to prevent fork
- **Graceful shutdown**: `atomic.Bool` prevents sends to closed channel; `recover()` protects worker goroutine

### JWT Security

- **Algorithm**: HS256 only (explicitly reject `none`)
- **Secret validation**: Length ≥ 32, ban default weak strings
- **Claims validation**: Explicit `exp`, `iat`, `iss`, `sub` checks
- **Type safety**: `sub` claim is strictly asserted as `string`
