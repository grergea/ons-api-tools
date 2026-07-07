# ONS SSL Certificate Skill — Design

## 배경

`ons-api-tools/ssl/`에 ONS CDN SSL 인증서 관리용 스크립트(`ssl_api_manager.py`, `ssl_workflow.py`)와 초안 `SKILL.md`가 이미 존재하지만, 다음 문제로 실제 Claude Code 스킬로 동작하지 않는다:

1. `.claude/skills/`에 설치되어 있지 않아 스킬로 인식되지 않음
2. 프론트매터가 Obsidian 노트 스타일과 뒤섞여 있고, 다른 설치된 스킬(평균 80~100줄) 대비 495줄로 과도하게 장황함
3. 공개 저장소(`ons-api-tools`, GitHub public)인데 실제 고객사 도메인명이 예시로 노출됨
4. "Hermes Agent Delegate Task" 섹션이 현재 사용 환경(Claude Code)과 무관
5. `verify_certificate_chain()`이 `{cert_dir}_2026032792EC5/RootChain/...`라는 특정 고객사 전용 디렉터리명을 하드코딩 — 다른 도메인에서는 체인 검증 불가
6. 로컬 인증서 저장 위치가 실제로는 `~/Certificate/{YYYYMMDD_도메인}/`(리포지토리 밖, 이미 실사용 중)인데, 스크립트는 `--cert-dir` 안에 `ssl.crt`/`ssl.key`/`fullchain.pem`이라는 고정 파일명이 있다고 가정 — 실제로는 CA 벤더가 제공하는 원본 파일명(`star_hani_com_cert.pem`, `Chain_RootCA_Bundle.crt`, `nopass_star_hani_com_key.pem` 등)이 그대로 있어 매번 수동 리네임·병합이 필요
7. 스크립트 노트가 `03_Resources/Scripts/ssl-api-manager.md`(오분류)와 `03_Resources/Scripts/CDN/ssl-api-manager.md`(정위치)에 완전히 동일한 내용으로 중복 존재

## 목표

ONS CDN(고객사) SSL 인증서를 **조회 / 신규등록 / 갱신**할 수 있는 Claude Code 스킬을 정식으로 설치하고, 위 문제를 모두 해결한다.

## 범위 밖 (Out of scope)

- ONS API 자체의 신규 엔드포인트 추가
- `ssl_api_manager.py`의 인증 방식 변경(API Key/password 방식 유지)
- Delegate Task/Hermes Agent 연동 (제거만 하고 재구축하지 않음)

## 설계

### 1. 스킬 설치 구조

```
/Users/shlee/mynotes/.claude/skills/ons-ssl-certificate/
├── SKILL.md              # 진입점. name+description 프론트매터만 사용
└── references/
    └── scenarios.md      # 시나리오별 전체 명령어, 출력 예시, 체인검증 세부사항
```

- 스크립트 본체(`ssl_api_manager.py`, `ssl_workflow.py`)는 `ons-api-tools/ssl/`에 그대로 유지 (경로만 참조)
- 기존 `ons-api-tools/ssl/SKILL.md`는 삭제. 저수준 CLI 레퍼런스는 기존 `README.md`가 계속 담당
- SKILL.md 프론트매터:
  ```yaml
  ---
  name: ons-ssl-certificate
  description: "ONS CDN SSL 인증서 관리 — 조회/신규등록/갱신/도메인변경/로컬-원격 비교. Triggers on: 'SSL 인증서 등록', '인증서 갱신', 'ONS 인증서 조회', '인증서 비교'."
  ---
  ```

### 2. 콘텐츠 정리

- 모든 예시 도메인을 실제 고객사명(`cdnbundle.ideadreamsoft.com`, `data.dsc4.net` 등)에서 `example.com`, `cdn.example.com`, `wildcard.example.com` 등 일반 예시로 치환
- "Delegate Task 실행 (Hermes Agent)" 섹션 삭제
- 시나리오 A~E(신규등록/갱신/도메인변경/조회/비교) 구조는 유지하되, SKILL.md에는 요약만 남기고 상세 출력 예시는 `references/scenarios.md`로 이동

### 3. 인증서 경로 컨벤션 변경 — `~/Certificate/{YYYYMMDD_도메인}/`

기존 실사용 컨벤션(`~/Certificate/20260702_hani.com/`, `~/Certificate/20260707_star_legendofymir_co_kr/`)을 정식 기본 경로로 채택한다.

**`--domain` 자동 탐지 (기존 옵션 확장, `ssl_workflow.py`의 `validate`/`compare`/`new`/`renew`/`domains`에 적용):**

> **주의(모호성 해소)**: `validate`/`compare`는 이미 `--domain`을 "인증서 Subject/SAN 일치 확인용"으로 사용 중이다. 이번 변경으로 `--domain`은 **경로 자동 탐지 + SAN 검증을 동시에 수행**하는 단일 옵션으로 통합한다 (같은 도메인 값이 두 목적에 그대로 재사용되므로 별도 플래그를 신설하지 않는다).

- `validate`/`compare`: `--cert-dir`를 선택값으로 변경. `--cert-dir` 생략 시 `--domain`이 필수가 되며, 경로 탐지 + 기존 SAN 검증 두 역할을 모두 수행. `--cert-dir`를 명시하면 기존처럼 경로만 그대로 사용하고 `--domain`은 SAN 검증에만 쓰인다 (하위 호환 유지)
- `new`/`renew`/`domains`: `--ssl-cert`/`--ssl-key`를 선택값으로 변경. 생략 시 `--domain`으로 자동 탐지된 cert/key 경로를 사용. `--ssl-cert`/`--ssl-key`를 명시하면 기존처럼 그 경로를 그대로 사용 (하위 호환 유지)
- `--domain hani.com` 입력 시 `~/Certificate/*_hani.com` glob 패턴으로 검색
- 매치가 여러 개면 날짜 접두사(`YYYYMMDD`) 기준 최신 폴더를 자동 선택
- 매치가 없으면 에러로 중단 (후보 없음을 명시)

**폴더 내 파일 자동 탐지 (신규 함수 `discover_cert_bundle(cert_dir)`):**

| 대상 | 탐지 패턴 | 비고 |
|------|----------|------|
| 인증서(leaf) | `*cert*.pem`, `*.crt` (chain/key 패턴 제외) | |
| 개인키 | `nopass_*key*` 우선 | 없으면 일반 `*key*.pem`/`*.key` |
| 체인(intermediate) | `Chain_*.crt`, `*chain*` | |
| 무시 대상 | `*.zip`, `.DS_Store` | Apache/NginX/IIS 번들 zip은 사용 안 함 |

- 패턴 매치가 모호(후보 0개 또는 2개 이상)하면 에러로 후보 목록을 보여주고 중단 — 잘못된 추정 방지
- `fullchain.pem`이 폴더에 이미 있으면 그대로 사용, 없으면 탐지된 cert+chain을 합쳐 자동 생성해 폴더에 캐시

**암호화된 개인키 자동 해독:**

- `nopass_*` 키가 없고 암호화된 키만 있는 경우:
  ```bash
  openssl rsa -in <encrypted_key> -passin env:_ONS_KEY_PASSIN -out <cert_dir>/nopass_<원본파일명>
  ```
- 비밀번호는 커맨드라인 인자로 넘기지 않고 실행 시점 임시 환경변수(`_ONS_KEY_PASSIN`)로 전달 (`ps` 노출 방지)
- 비밀번호 소스: `--ssl-key-password` 플래그 또는 `ONS_SSL_KEY_PASSWORD` 환경변수 (기존 `ONS_API_KEY` 패턴과 동일)
- 해독 성공 시 `nopass_<원본파일명>`으로 폴더에 캐시 저장 (다음 실행부터 재사용, 기존 실사용 폴더의 명명 규칙과 동일)
- 비밀번호 미제공 + 암호화된 키만 존재 시: 에러로 중단하고 필요한 플래그/환경변수 안내

### 4. 체인 검증 버그 수정

`verify_certificate_chain()`에서 `{cert_dir}_2026032792EC5/RootChain/...` 하드코딩 의존성 제거:

- 자동 생성/확인된 `fullchain.pem`에 포함된 인증서(leaf + intermediate)만 파싱해 사용
- intermediate는 `-untrusted`로 전달, 최상위 신뢰는 시스템 기본 CA 저장소(OS trust store) 사용
- 외부 `RootChain` 디렉터리 참조를 완전히 제거 → 임의의 고객사/도메인에서 동일하게 동작

### 5. 볼트 정리

- `03_Resources/Scripts/ssl-api-manager.md` (오분류, `CDN/` 버전과 100% 동일 확인됨) 삭제
- `03_Resources/Scripts/CDN/ssl-api-manager.md`, `03_Resources/Scripts/CDN/ssl_workflow.md`에 다음 반영:
  - `updated` 날짜 갱신
  - 체인 검증 버그 수정 및 `~/Certificate/` 경로 자동 탐지 기능을 "주요 기능"/"사용법" 섹션에 반영
  - 새로 설치되는 `.claude/skills/ons-ssl-certificate` 스킬 링크 추가

## 테스트 계획

- 기존 실제 폴더 `~/Certificate/20260702_hani.com/`, `~/Certificate/20260707_star_legendofymir_co_kr/`를 대상으로 `ssl_workflow.py validate --domain hani.com` 실행 → 자동 탐지·체인검증이 하드코딩 없이 동작하는지 확인
- 인증서 파일이 없는 임의 도메인으로 `--domain`을 지정했을 때 명확한 에러 메시지가 나오는지 확인
- 암호화된 키만 있는 폴더(재현용 테스트 데이터)로 `--ssl-key-password`/`ONS_SSL_KEY_PASSWORD` 경로 모두 검증
- 기존 `ons-api-tools/ssl/certs/*` 테스트 데이터로 회귀 확인 (기존 `--cert-dir` 방식이 여전히 동작하는지)

## 커밋/동기화 규칙

- `ons-api-tools` 저장소: 코드 변경(`ssl_workflow.py`) + `README.md`(필요 시) 함께 커밋, `master` 브랜치, 민감정보 미포함 확인 후 push
- `mynotes` 저장소(비-git, 볼트): `.claude/skills/ons-ssl-certificate/` 신설, 관련 스크립트 노트 업데이트, 중복 노트 삭제
