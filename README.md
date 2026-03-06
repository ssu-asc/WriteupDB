# ASC Writeup DB

ASC 보안 동아리 CTF Writeup 관리 시스템

멤버가 Git PR로 writeup을 제출하면, 관리자 리뷰 후 merge 시 자동으로 Notion DB에 동기화됩니다.

## 구조

```
writeups/
└── {YYYY-CTF이름}/
    └── {카테고리}/
        └── {문제명}/
            ├── README.md      # writeup 본문 (frontmatter 포함)
            ├── solve.py       # 풀이 스크립트 (선택)
            └── images/        # 스크린샷 (선택)
```

## 빠른 시작

### 1. 레포 Fork & Clone

```bash
# 본인 GitHub 계정으로 Fork 후
git clone https://github.com/<your-username>/WriteupDB.git
cd WriteupDB
```

### 2. Writeup 작성

```bash
# 디렉토리 생성
mkdir -p writeups/2026-Example-CTF/web/example-challenge

# 템플릿 복사
cp templates/writeup-template.md writeups/2026-Example-CTF/web/example-challenge/README.md

# writeup 작성
```

### 3. 로컬 검증

```bash
pip install -r scripts/requirements.txt
python scripts/validate_frontmatter.py
```

### 4. PR 제출

```bash
git checkout -b writeup/2026-Example-CTF/example-challenge
git add .
git commit -m "Add writeup: 2026-Example-CTF/web/example-challenge"
git push origin writeup/2026-Example-CTF/example-challenge
# GitHub에서 PR 생성
```

자세한 제출 방법은 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

## 파이프라인

```
[멤버] -> fork/branch -> [PR 제출] -> 리뷰 -> [merge] -> [GitHub Actions] -> [Notion DB]
                              |                              |
                        CI: frontmatter 검증         변경된 .md 파싱 -> 동기화
```

## 설정 (관리자)

### GitHub Secrets

| Secret | 설명 |
|--------|------|
| `NOTION_API_KEY` | Notion Internal Integration Token |
| `NOTION_DATABASE_ID` | 대상 Notion DB ID |

### Notion DB 스키마

| 속성명 | 타입 | 비고 |
|--------|------|------|
| 문제명 | Title | PK 역할 |
| CTF명 | Rich Text | |
| 카테고리 | Select | WEB/PWN/REV/CRYPTO/MISC |
| 난이도 | Select | easy/medium/hard/insane |
| 작성자 | Rich Text | |
| 날짜 | Date | |
| 점수 | Number | |
| 태그 | Multi-select | 사용 기술/툴 |
| GitHub 링크 | URL | writeup 원문 링크 |

### 브랜치 보호 규칙 (권장)

- `main` 브랜치 직접 push 금지
- PR 필수, CI 통과 필수
- 최소 1명 리뷰 승인 필수
