# Writeup 제출 가이드

## 제출 절차

### 1. Fork & Clone

이 레포를 본인 GitHub 계정으로 Fork한 뒤 Clone합니다.

```bash
git clone https://github.com/<your-username>/WriteupDB.git
cd WriteupDB
```

### 2. 브랜치 생성

```bash
git checkout -b writeup/<CTF이름>/<문제명>
# 예: git checkout -b writeup/2026-DiceCTF/web/babyxss
```

### 3. 디렉토리 및 파일 생성

디렉토리 네이밍 규칙:

```
writeups/{YYYY-CTF이름}/{카테고리}/{문제명}/
```

- **CTF이름**: `YYYY-CTF이름` 형식 (예: `2026-DiceCTF`, `2026-DEFCON-Quals`)
- **카테고리**: 소문자 (`web`, `pwn`, `rev`, `crypto`, `misc`)
- **문제명**: 소문자, 공백은 하이픈으로 (예: `baby-xss`, `heap-note`)

```bash
mkdir -p writeups/2026-DiceCTF/web/baby-xss
cp templates/writeup-template.md writeups/2026-DiceCTF/web/baby-xss/README.md
```

### 4. Writeup 작성

`README.md`의 YAML frontmatter를 반드시 작성합니다.

#### 필수 필드

| 필드 | 설명 | 예시 |
|------|------|------|
| `ctf_name` | CTF 대회명 | `DiceCTF 2026` |
| `challenge_name` | 문제명 | `baby-xss` |
| `category` | 카테고리 | `web` |
| `difficulty` | 난이도 | `easy` |
| `author` | 작성자 (GitHub username) | `alice` |
| `date` | 대회 날짜 | `2026-01-15` |

#### 선택 필드

| 필드 | 설명 | 예시 |
|------|------|------|
| `points` | 문제 배점 | `500` |
| `tags` | 관련 기술/툴 | `[XSS, CSP bypass]` |

#### 카테고리 유효값

`web`, `pwn`, `rev`, `crypto`, `misc`

#### 난이도 유효값

`easy`, `medium`, `hard`, `insane`

### 5. 로컬 검증

```bash
pip install -r scripts/requirements.txt
python scripts/validate_frontmatter.py
```

### 6. Commit & Push

```bash
git add writeups/2026-DiceCTF/web/baby-xss/
git commit -m "Add writeup: DiceCTF 2026 - baby-xss (web)"
git push origin writeup/2026-DiceCTF/baby-xss
```

### 7. Pull Request

GitHub에서 PR을 생성합니다. PR 템플릿을 채워주세요.

## 추가 파일

- `solve.py`, `exploit.py` 등 풀이 스크립트 첨부 가능
- 스크린샷은 `images/` 디렉토리에 저장
- writeup 본문에서 상대 경로로 참조: `![screenshot](images/step1.png)`

## 주의사항

- 실제 CTF 플래그는 가급적 마스킹 처리 (예: `flag{REDACTED}`)
- 대용량 바이너리 파일은 가급적 첨부하지 않기
- frontmatter 검증 CI가 통과해야 merge 가능
