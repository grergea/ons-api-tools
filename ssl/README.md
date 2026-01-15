# SSL API Manager

ONS CDN 플랫폼의 SSL 인증서를 API를 통해 관리하는 Python CLI 도구입니다.

## Features

- **staging-deploy**: 신규 SSL 인증서를 Staging 환경에 배포
- **staging-update**: 기존 인증서 수정 또는 도메인 추가/삭제
- **deploy**: Staging에서 검증된 인증서를 운영 환경에 최종 배포
- **staging-cancel**: Staging 배포 취소
- **history**: 인증서 배포 이력 조회

## Requirements

```bash
pip install requests
```

## Authentication

다음 두 가지 인증 방식 중 하나를 선택하여 사용합니다:

| 방식 | 파라미터 | 설명 |
|------|----------|------|
| 비밀번호 | `--password` | User Portal 계정 비밀번호 |
| API Key | `--api-key` | User Portal에서 발급받은 API KEY |

## Usage

### 신규 인증서 Staging 배포

```bash
python ssl_api_manager.py staging-deploy \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-cert /path/to/certificate.crt \
    --ssl-key /path/to/private.key \
    --domain-list "example.com,www.example.com" \
    --memo "2026년 1월 인증서 등록"
```

### 인증서 갱신 (Staging)

```bash
python ssl_api_manager.py staging-update \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com \
    --ssl-cert /path/to/new_certificate.crt \
    --ssl-key /path/to/new_private.key
```

### 도메인 추가/삭제 (Staging)

```bash
python ssl_api_manager.py staging-update \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com \
    --add-domain-list "api.example.com" \
    --del-domain-list "old.example.com"
```

### 최종 배포

```bash
python ssl_api_manager.py deploy \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com
```

### Staging 취소

```bash
python ssl_api_manager.py staging-cancel \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com
```

### 배포 이력 조회

```bash
python ssl_api_manager.py history \
    --id <USER_ID> \
    --api-key <API_KEY> \
    --ssl-file-name example.com
```

## Options Reference

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

## Response Example

### Success

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

### Response Codes

| result_code | result_msg | 의미 |
|-------------|------------|------|
| 200 | success | 요청 성공 |
| 400 | - | 잘못된 요청 파라미터 |
| 401 | - | 인증 실패 |
| 500 | - | 서버 내부 오류 |
