# CLAUDE.md

이 파일은 Claude Code가 이 저장소에서 작업할 때 참고하는 가이드입니다.

## 저장소 정보

- **이름**: ons-api-tools
- **GitHub**: https://github.com/grergea/ons-api-tools (**공개 저장소** — 민감정보 절대 금지)
- **브랜치**: master (`git push origin master`)
- **용도**: ONS API 도구 (SSL 인증서 관련 스크립트는 `ssl/` 하위)

## 작업 규칙

### 커밋 전 필수 확인

- **민감정보 검사**: API 키·토큰·인증서 개인키·내부 호스트명이 코드/설정에 포함되지 않았는지 diff 전체 확인. 인증 정보가 필요한 스크립트는 이 저장소가 아닌 `scripts-local`로 이동
- **스크립트 노트 동기화**: `/Users/shlee/mynotes/03_Resources/Scripts/CDN/[스크립트명].md` 업데이트 (볼트는 git 저장소가 아니므로 커밋 대상은 코드뿐)

### 커밋 메시지 형식

Conventional Commits (`<type>(<scope>): <subject>`). Types: feat, fix, refactor, perf, docs, test, chore, build, ci, style, revert. 명령형, subject ≤50자 권장(최대 72자), 마침표 없음. body는 "왜"가 자명하지 않을 때만 추가. 커밋 메시지는 `caveman-commit` 스킬로 생성한다.
