# SSL Certificate Tools

ONS CDN 플랫폼의 SSL 인증서를 관리하는 Python CLI 도구 모음입니다.

| 스크립트 | 역할 |
|---------|------|
| `ssl_workflow.py` | 워크플로우 자동화 (**권장 진입점**) — 로컬 검증 → staging 배포 → 검증 → 최종 배포를 한 번에 |
| `ssl_api_manager.py` | ONS CDN SSL API raw CLI (`ssl_workflow.py`가 내부적으로 호출) |
| `cert_discovery.py` | `~/Certificate/{YYYYMMDD}_{domain}/` 규칙 기반 인증서 파일 자동 탐지 헬퍼 (라이브러리 모듈, 직접 실행하지 않음) |

## Requirements

```bash
pip install requests
```

## Authentication

```bash
export ONS_API_KEY="<User Portal에서 발급받은 API 키>"
export ONS_API_ID="cdnetworks"   # 기본값, 생략 가능
```

두 스크립트 모두 `--id`/`--api-key` 플래그로 override 가능합니다. 암호화된 개인키를 다루는 경우:

```bash
export ONS_SSL_KEY_PASSWORD="<키 암호>"   # 또는 --ssl-key-password 로 매번 지정
```

## SSL Certificate Workflow (`ssl_workflow.py`) — 권장 진입점

`--domain <도메인>` 옵션을 지정하면 `~/Certificate/{YYYYMMDD}_{도메인}/` 폴더를 자동 탐색해 CA가 제공한 원본 파일명 그대로 cert/key/chain을 찾고 `fullchain.pem`을 생성합니다 (파일명 rename 불필요, 암호화된 키는 자동 복호화). 폴더/파일을 직접 지정하려면 `--cert-dir`/`--ssl-cert`/`--ssl-key`를 써도 됩니다.

`new`/`renew`/`domains` 워크플로우는 내부적으로 `staging-* → lookup --verify → deploy` 순서로 실행되며, 검증만 하고 최종 배포는 나중에 하려면 `--no-auto-deploy`를 붙입니다.

### Commands

| 명령 | 용도 |
|------|------|
| `validate --domain <도메인>` | 로컬 인증서 검증 (만료일, 키 일치, 체인) |
| `new --ssl-file-name <이름> --domain <도메인> --domain-list "..."` | 신규 인증서 등록 |
| `renew --ssl-file-name <이름> --domain <도메인>` | 기존 인증서 갱신 |
| `domains --ssl-file-name <이름> --add-domain-list "..."` | 도메인 매핑 변경 |
| `lookup --ssl-file-name <이름> --verify` | ONS CDN에서 인증서 정보 조회 |
| `compare --domain <도메인> --ssl-file-name <이름>` | 로컬 vs ONS CDN 인증서 비교 |
| `list --domain <도메인>` | 등록된 인증서 목록 조회 (`ssl-file-name`을 모를 때 검색) |

### Usage Examples

```bash
# 로컬 인증서 검증
python3 ssl_workflow.py validate --domain example.com

# 신규 인증서 등록
python3 ssl_workflow.py new --ssl-file-name example.com --domain example.com \
    --domain-list "cdn.example.com"

# 기존 인증서 갱신
python3 ssl_workflow.py renew --ssl-file-name example.com --domain example.com

# 도메인 매핑 변경
python3 ssl_workflow.py domains --ssl-file-name example.com \
    --add-domain-list "new.example.com"

# ONS CDN 인증서 조회 (검증 포함)
python3 ssl_workflow.py lookup --ssl-file-name example.com --verify

# 로컬 vs ONS CDN 인증서 비교
python3 ssl_workflow.py compare --domain example.com --ssl-file-name example.com

# 도메인으로 등록된 ssl-file-name 검색
python3 ssl_workflow.py list --domain example.com
```

### Common Options

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--id` | Account ID | `cdnetworks` |
| `--api-key` | API Key | (env `ONS_API_KEY`) |
| `--skip-verify` | 검증 단계 건너뜀 | false |
| `--no-auto-deploy` | 최종 배포 건너뜀 | false |

### Rollback

Staging 배포를 취소하려면 `ssl_api_manager.py`의 `staging-cancel`을 직접 사용합니다 (아래 참고).

## SSL API Manager (`ssl_api_manager.py`) — raw API CLI

`ssl_workflow.py`가 내부적으로 호출하는 raw API CLI입니다. 워크플로우 없이 개별 API를 직접 호출하고 싶을 때 사용합니다.

### Features

- **staging-deploy**: 신규 SSL 인증서를 Staging 환경에 배포
- **staging-update**: 기존 인증서 수정 또는 도메인 추가/삭제
- **deploy**: Staging에서 검증된 인증서를 운영 환경에 최종 배포
- **staging-cancel**: Staging 배포 취소
- **history**: 인증서 배포 이력 조회
- **lookup**: Staging 서버에서 인증서 정보 조회 (openssl 검증 포함, `--verify`)
- **list**: 등록된 전체 SSL 인증서 목록 조회 (`--domain`으로 필터링)

### Usage Examples

```bash
# 신규 인증서 Staging 배포
python ssl_api_manager.py staging-deploy \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-cert /path/to/certificate.crt \
    --ssl-key /path/to/private.key \
    --domain-list "example.com,www.example.com" \
    --memo "2026년 1월 인증서 등록"

# 인증서 갱신 (Staging)
python ssl_api_manager.py staging-update \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com \
    --ssl-cert /path/to/new_certificate.crt \
    --ssl-key /path/to/new_private.key

# 도메인 추가/삭제 (Staging)
python ssl_api_manager.py staging-update \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com \
    --add-domain-list "api.example.com" \
    --del-domain-list "old.example.com"

# 최종 배포
python ssl_api_manager.py deploy \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com

# Staging 취소
python ssl_api_manager.py staging-cancel \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com

# 배포 이력 조회
python ssl_api_manager.py history \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com

# 등록된 인증서 목록 조회 (도메인으로 검색)
python ssl_api_manager.py list \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --domain example.com
```

### Options Reference

| 명령어 | 옵션 | 필수 | 설명 |
|--------|------|:----:|------|
| 공통 | `--id` | O | User Portal 계정 ID |
| 공통 | `--password` | 택1 | 계정 비밀번호 |
| 공통 | `--api-key` | 택1 | API KEY |
| staging-deploy | `--ssl-cert` | O | 인증서 파일 경로 |
| staging-deploy | `--ssl-key` | O | 개인키 파일 경로 |
| staging-deploy | `--ssl-key-password` | - | 암호화된 키 비밀번호 |
| staging-deploy | `--domain-list` | - | 배포 도메인 목록 (쉼표 구분) |
| staging-deploy | `--memo` | - | 메모 |
| staging-update | `--ssl-file-name` | O | 인증서 파일명 (확장자 제외) |
| staging-update | `--ssl-cert` | - | 갱신할 인증서 파일 |
| staging-update | `--ssl-key` | - | 갱신할 개인키 파일 |
| staging-update | `--add-domain-list` | - | 추가할 도메인 목록 |
| staging-update | `--del-domain-list` | - | 삭제할 도메인 목록 |
| deploy | `--ssl-file-name` | O | 배포할 인증서 파일명 |
| staging-cancel | `--ssl-file-name` | O | 취소할 인증서 파일명 |
| history | `--ssl-file-name` | O | 조회할 인증서 파일명 |
| lookup | `--ssl-file-name` | O | 조회할 인증서 파일명 |
| lookup | `--verify` | - | openssl 기반 인증서 검증 수행 |
| list | `--domain` | - | 도메인 부분 일치로 결과 필터링 |

### Response Example

#### Success

```json
{
    "api_response": {
        "result_msg": "success",
        "result_code": "200",
        "data": {
            "ssl_file_name": "example.com",
            "domain_list": "http://example.com"
        }
    }
}
```

#### Response Codes

| result_code | result_msg | 의미 |
|-------------|------------|------|
| 200 | success | 요청 성공 |
| 400 | - | 잘못된 요청 파라미터 |
| 401 | - | 인증 실패 |
| 500 | - | 서버 내부 오류 |

## cert_discovery.py (내부 헬퍼 모듈)

`ssl_workflow.py`가 `--domain` 옵션 처리 시 import하는 라이브러리 모듈입니다. 직접 CLI로 실행하지 않습니다. CA마다 제각각인 인증서/키/체인 파일명을 정규식으로 자동 식별하고, 암호화된 키를 복호화하며, cert+chain을 `fullchain.pem`으로 병합합니다. 자세한 내용은 스크립트 상단 docstring과 각 함수의 docstring을 참고하세요.
