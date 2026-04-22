---
name: ssl-certificate-workflow
description: ONS CDN SSL 인증서 관리 워크플로우 자동화 — 신규 등록, 갱신, 도메인 변경, 조회, 검증 시나리오별 자동 실행
category: automation
tags:
  - ssl
  - certificate
  - CDN
  - workflow
  - automation
author:
  - "[[이상훈]]"
created: 2026-04-22
updated: 2026-04-22
status: completed
version: 2.0.0
requires:
  - ssl_api_manager.py
  - python3.11+
  - openssl
---

# SSL Certificate Workflow Automation

ONS CDN SSL 인증서 관리 워크플로우 자동화 스킬입니다.

## 개요

고객사 인증서 등록/갱신 작업을 **Delegate Task**를 통해 자동 실행합니다.

```
신규등록 → staging-deploy → lookup(검증) → deploy(최종 배포)
갱신     → staging-update → lookup(검증) → deploy(최종 배포)
도메인변경 → staging-update → lookup(검증) → deploy(최종 배포)
조회     → lookup(정보 확인만)
```

## 디렉터리 구조

인증서 파일은 다음 구조로 정리합니다:

```
ons-api-tools/ssl/
├── ssl_api_manager.py
├── ssl_workflow.py          # 워크플로우 자동화 스크립트
└── certs/
    └── {domain}/
        ├── ssl.crt          # 서버 인증서 (server certificate)
        ├── ca-chain.crt     # 체인 인증서 (intermediate + root)
        ├── fullchain.pem     # 병합 인증서 (ssl.crt + ca-chain.crt)
        └── ssl.key          # 개인키 (private key)
```

### 인증서 병합 방법

```bash
# fullchain.pem 생성 (서버 인증서 + 체인 인증서)
cat certs/{domain}/ssl.crt certs/{domain}/ca-chain.crt > certs/{domain}/fullchain.pem

# 검증
openssl verify -CAfile certs/{domain}/ca-chain.crt certs/{domain}/ssl.crt
```

### 인증서 검증 명령어

```bash
# 1. 인증서 정보 확인
openssl x509 -in certs/{domain}/ssl.crt -noout -dates -subject -issuer

# 2. 개인키와 인증서 일치 확인 (modulus 비교)
openssl x509 -noout -modulus -in certs/{domain}/ssl.crt | openssl md5
openssl rsa -noout -modulus -in certs/{domain}/ssl.key | openssl md5
# 두 결과가 같아야 함

# 3. 개인키 비밀번호 확인
openssl rsa -check -in certs/{domain}/ssl.key

# 4. 체인 검증
openssl verify -CAfile certs/{domain}/ca-chain.crt certs/{domain}/ssl.crt
```

## 스크립트

| 파일 | 설명 |
|------|------|
| `ssl_workflow.py` | 워크플로우 자동화 실행 스크립트 (`ssl/` 디렉토리) |
| `ssl_api_manager.py` | SSL API CLI 관리자 (`ssl/` 디렉토리, GitHub 관리) |

## 사용 전 준비

### 1. 인증 정보 설정

`ssl_workflow.py` 상단의 기본 인증 정보를 설정합니다:

```python
DEFAULT_AUTH = {
    "id": "cdnetworks",
    "api_key": "d3a5acf9-b537-4a30-a269-c95d1c599bcd"
}
```

### 2. 의존성 확인

```bash
pip install requests
```

## 인증서 디렉터리 구조

인증서 파일은 다음 구조로 정리합니다:

```
ons-api-tools/ssl/certs/{domain}/
├── ssl.crt          # 서버 인증서
├── ssl.key          # 개인키
└── fullchain.pem    # 전체 체인 인증서 (서버인증서 + 중간/루트 인증서)
```

### 파일 설명

| 파일 | 설명 | 생성 방법 |
|------|------|----------|
| `ssl.crt` | 서버 인증서 (단일 인증서) | 원본 인증서 파일 |
| `ssl.key` | RSA 개인키 | 원본 키 파일 |
| `fullchain.pem` | 전체 인증서 체인 | `cat server.crt ca-chain.pem > fullchain.pem` |

### 인증서 검증 (validate)

```bash
python3 ssl_workflow.py validate \
  --cert-dir /path/to/certs/cdnbundle.ideadreamsoft.com \
  --domain cdnbundle.ideadreamsoft.com
```

**검증 항목 (전체 4레벨):**
| 단계 | 검증 항목 | 설명 |
|------|----------|------|
| 1 | 인증서 만료일 | 유효기간 확인, 30일 이하 경고 |
| 2 | 개인키 유효성 | `openssl rsa -check` 통과 여부 |
| 3 | 개인키/인증서 일치 | modulus 비교 |
| 4 | 인증서 체인 검증 | `openssl verify`로 전체 체인 검증 |

**체인 검증 구조:**
```
[AAA Certificate Services]        ← 루트 CA (Self-signed)
        ↑
[USERTrust RSA Certification Authority]  ← 중간 CA
        ↑
[GoGetSSL RSA DV CA]              ← 중간 CA
        ↑
[cdnbundle.ideadreamsoft.com]      ← 서버 인증서
```

**체인 검증 출력 예시:**
```
Certificate Chain Verification:
  Chain Status: OK
  Chain (4 certificates):
    1. cdnbundle.ideadreamsoft.com
    2. GoGetSSL RSA DV CA
    3. USERTrust RSA Certification Authority
    4. AAA Certificate Services
```

**참고:** 체인 검증 시 루트 인증서 파일은 `{domain}_2026032792EC5/RootChain/` 디렉터리에서 자동 탐색합니다.

---

## 사용법

### CLI 실행

```bash
python3 ssl_workflow.py <command> [options]
```

### 명령어일

| 명령 | 설명 |
|------|------|
| `validate` | 로컬 인증서 파일 검증 (만료일, 키 일치, 도메인 확인) |
| `new` | 신규 인증서 등록 |
| `renew` | 기존 인증서 갱신 |
| `domains` | 도메인 매핑 변경 |
| `lookup` | ONS CDN에서 인증서 정보 조회 |
| `compare` | 로컬 인증서 vs ONS CDN 인증서 비교 |

---

## 시나리오별 사용법

### 시나리오 A: 신규 인증서 등록

```bash
python3 ssl_workflow.py new \
  --ssl-file-name wildcard.example.com \
  --ssl-cert /path/to/fullchain.pem \
  --ssl-key /path/to/key.pem \
  --domain-list "cdn.example.com,api.example.com" \
  --memo "2026년 4월 신규 인증서 등록"
```

**워크플로우 흐름:**

```
1. staging-deploy (스테이징 배포)
   ↓
2. lookup --verify (검증)
   - Staging IP 추출
   - 인증서 정보 확인 (만료일, Subject, SAN)
   - 유효기간 30일 이하 경고
   ↓ 성공
3. deploy (최종 배포)
   ↓
4. 완료 요약 출력
```

**실제 명령어:**
```bash
python3 ssl_api_manager.py staging-deploy \
  --id cdnetworks --api-key d3a5acf9-b537-4a30-a269-c95d1c599bcd \
  --ssl-cert fullchain.pem --ssl-key key.pem \
  --domain-list "cdn.example.com,api.example.com" \
  --memo "2026년 4월 신규 인증서 등록"
```

---

### 시나리오 B: 기존 인증서 갱신

```bash
python3 ssl_workflow.py renew \
  --ssl-file-name data.dsc4.net \
  --ssl-cert ./certs/data.dsc4.net/fullchain.pem \
  --ssl-key ./certs/data.dsc4.net/ssl.key \
  --memo "2026년 4월 인증서 갱신"
```

**워크플로우 흐름:**

```
1. staging-update (인증서 교체)
   ↓
2. lookup --verify (검증)
   - 새 인증서 정보 확인
   - 만료일 확인
   ↓ 성공
3. deploy (최종 배포)
   ↓
4. 완료 요약 출력
```

**실제 명령어:**
```bash
python3 ssl_api_manager.py staging-update \
  --id cdnetworks --api-key d3a5acf9-b537-4a30-a269-c95d1c599bcd \
  --ssl-file-name data.dsc4.net \
  --ssl-cert certs/data.dsc4.net/fullchain.pem \
  --ssl-key certs/data.dsc4.net/ssl.key \
  --memo "2026년 4월 인증서 갱신"
```

---

### 시나리오 C: 도메인 매핑 변경

**도메인 추가:**
```bash
python3 ssl_workflow.py domains \
  --ssl-file-name wildcard.example.com \
  --add-domain-list "new.example.com,extra.example.com" \
  --memo "도메인 추가"
```

**도메인 삭제:**
```bash
python3 ssl_workflow.py domains \
  --ssl-file-name wildcard.example.com \
  --del-domain-list "old.example.com" \
  --memo "도메인 삭제"
```

**실제 명령어:**
```bash
# 추가
python3 ssl_api_manager.py staging-update \
  --id cdnetworks --api-key d3a5acf9-b537-4a30-a269-c95d1c599bcd \
  --ssl-file-name wildcard.example.com \
  --add-domain-list "new.example.com,extra.example.com"

# 삭제
python3 ssl_api_manager.py staging-update \
  --id cdnetworks --api-key d3a5acf9-b537-4a30-a269-c95d1c599bcd \
  --ssl-file-name wildcard.example.com \
  --del-domain-list "old.example.com"
```

---

### 시나리오 D: 인증서 정보 조회

```bash
# 기본 조회 (Staging IP, 배포 상태)
python3 ssl_workflow.py lookup --ssl-file-name data.dsc4.net

# 상세 검증 포함 (인증서 정보, 만료일, 체인 검증)
python3 ssl_workflow.py lookup --ssl-file-name data.dsc4.net --verify
```

**실제 명령어:**
```bash
# 기본 조회
python3 ssl_api_manager.py lookup \
  --id cdnetworks --api-key d3a5acf9-b537-4a30-a269-c95d1c599bcd \
  --ssl-file-name data.dsc4.net

# 상세 검증
python3 ssl_api_manager.py lookup \
  --id cdnetworks --api-key d3a5acf9-b537-4a30-a269-c95d1c599bcd \
  --ssl-file-name data.dsc4.net --verify
```

---

### 시나리오 E: 로컬 vs ONS CDN 인증서 비교 (compare)

로컬 인증서 파일과 ONS CDN에 배포된 인증서를 비교하여 **동일 여부를 확인**합니다.

**사용 시점:**
- 갱신 전: 새 인증서가 기존 것과 다른지 확인
- 갱신 후: ONS CDN에 올바른 인증서가 배포되었는지 확인
- 주기적: 배포된 인증서와 로컬 파일의 일치 여부 검증

```bash
python3 ssl_workflow.py compare \
  --cert-dir /path/to/certs/cdnbundle.ideadreamsoft.com \
  --ssl-file-name cdnbundle.ideadreamsoft.com \
  --domain cdnbundle.ideadreamsoft.com
```

**비교 항목 (5가지):**
| 항목 | 설명 |
|------|------|
| Serial | 인증서 일련번호 |
| Domain (CN) |Common Name |
| 만료일 | Expiry Date |
| 남은 일수 | Days Left |
| Issuer | 인증서 발급자 |

**출력 예시:**
```
[1/3] 로컬 인증서 검증: /path/to/certs/cdnbundle.ideadreamsoft.com
============================================================
[SUCCESS] Private key matches certificate
[SUCCESS] Certificate chain verified (2 certificates)
[SUCCESS] 로컬 인증서 유효함 (만료일: Oct 15 23:59:59 2026 GMT)

[2/3] ONS CDN 인증서 조회: cdnbundle.ideadreamsoft.com
============================================================
[WARNING] Staging IP not found in history, attempting DNS resolution...
[SUCCESS] Resolved cdnbundle.ideadreamsoft.com -> 211.56.106.109
[SUCCESS] ONS CDN 인증서 조회 성공 (Staging IP: 211.56.106.109)

[3/3] 비교 결과
============================================================

================================================================================
Certificate Comparison: Local vs ONS CDN
================================================================================
항목                   로컬                                  ONS CDN                             상태
----------------------------------------------------------------------------------------------------
Serial               6BF131BB35468F9201C621EFFEDD4D15    6BF131BB35468F9201C621EFFEDD4D15    ✓
Domain (CN)          cdnbundle.ideadreamsoft.com         cdnbundle.ideadreamsoft.com         ✓
만료일                  Oct 15 23:59:59 2026 GMT            Oct 15 23:59:59 2026 GMT            ✓
남은 일수                176일                                176일                                ✓
Issuer               GoGetSSL RSA DV CA                  GoGetSSL RSA DV CA                  ✓
====================================================================================================

결과: 로컬과 ONS CDN 인증서가 동일합니다 (업로드 불필요)

============================================================
[SUCCESS] Workflow completed successfully
```

**동작 순서:**
1. 로컬 인증서 검증 (만료일, 키-인증서 일치, 체인 검증)
2. ONS CDN 인증서 조회 (staging history → DNS resolution fallback)
3. 5개 항목 비교 결과 출력

**결론 기준:**
- Serial이 동일하면 → "업로드 불필요"
- Serial이 다르면 → "업로드 필요"

---

## Delegate Task 실행

Hermes Agent를 통해 워크플로우를 자동 실행할 수 있습니다.

### Delegate Task 예시

**갱신 워크플로우 실행:**
```
goal: |
  ONS CDN SSL 인증서 갱신 워크플로우를 자동 실행합니다.

  인증서: data.dsc4.net
  인증서 파일: ./certs/data.dsc4.net/crt.crt
  개인키 파일: ./certs/data.dsc4.net/key.key
  메모: 2026년 4월 인증서 갱신

  1. staging-update 실행
  2. lookup --verify 로 검증
  3. deploy 로 최종 배포
  4. 결과를 요약하여 Slack으로 전송

  스크립트 경로: /Users/shlee/leesh/mynotes/ons-api-tools/ssl/ssl_api_manager.py
  인증정보: id=cdnetworks, api-key=d3a5acf9-b537-4a30-a269-c95d1c599bcd
```

**조회만 실행:**
```
goal: |
  SSL 인증서 정보를 조회합니다.

  인증서: data.dsc4.net
  검증 포함: true

  스크립트 경로: /Users/shlee/leesh/mynotes/ons-api-tools/ssl/ssl_api_manager.py
  인증정보: id=cdnetworks, api-key=d3a5acf9-b537-4a30-a269-c95d1c599bcd
```

---

## 롤백

Staging 배포 후 문제가 발견되면 취소할 수 있습니다.

```bash
python3 ssl_api_manager.py staging-cancel \
  --id cdnetworks --api-key d3a5acf9-b537-4a30-a269-c95d1c599bcd \
  --ssl-file-name wildcard.example.com
```

---

## 출력 예시

### lookup --verify 성공 시

```
============================================================
SSL Certificate Lookup: data.dsc4.net
============================================================
Staging Server IP: 211.56.106.25
Staging Deploy Time: 2026-02-10 11:26:05
Deploy Status: Deployed
============================================================

[Verifying certificate on 211.56.106.25...]

Certificate Details:
  Subject: CN=data.dsc4.net
  Issuer: C=BE; O=GlobalSign nv-sa; CN=GlobalSign GCC R6 AlphaSSL CA 2025
  Serial: 038C4CD8502ED2C5C3D6
  Valid From: Jan 22 22:20:01 2026 GMT
  Valid Until: Feb 23 22:20:00 2027 GMT
  Status: [VALID - 307 days]
  Chain Verification: OK

  CNAME: data.dsc4.net.58.wskam.com
  Service Domain: data.dsc4.net
  Success Rate: 100%
```

### 만료 임박 인증서

```
  Status: [EXPIRES IN 25 DAYS]
```

### 만료된 인증서

```
  Status: [EXPIRED]
```

---

## 관련 문서
- [[SSL 인증서 업로드 절차 (API)]] — 전체 절차 문서
- [[data.dsc4.net 기존 인증서 갱신]] — 실제 갱신 사례
- [[ssl_api_manager.py]] — CLI 스크립트 상세
