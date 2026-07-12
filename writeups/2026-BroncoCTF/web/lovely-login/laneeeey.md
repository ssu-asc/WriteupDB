---
ctf_name: "BroncoCTF"
challenge_name: "Lovely Login"
category: "web"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "laneeeey"
date: "2026-07-12"
points: 10
tags: [robots-txt, base64]
---

# 문제명

## 문제 설명

Welcome to our lovely new login page 💕. The developers swear it’s secure… but they may have forgotten to clean up a few things before launch. Can you figure out how authentication works and log in as the right user? P.S. please follow my wishes and do not scrape it...

- https://broncoctf-lovely-login.chals.io/

## 풀이

### 분석

관리자 계정으로 로그인하여 플래그를 획득하는 웹(Web) 문제였다.

웹 서버의 robots.txt 파일을 확인하였다.

```
User-agent: *
Disallow: /security

# amVmZixzYXJhaCx hZG1pbixndWVzdA==
```

Disallow를 통해 /security 페이지가 존재함을 확인할 수 있었고 주석에는 Base64로 인코딩된 문자열이 포함되어 있었다.

해당 문자열을 Base64로 디코딩한 결과 다음과 같은 사용자 목록을 얻을 수 있었다.

```
jeff,sarah,admin,guest
```

이후 /security에 접속하여 추가 힌트를 확인하였다.

```
Internal Security Notes
Status: Work in progress

Passwords are derived from usernames
Current implementation stores them backwards for obfuscation
Planned upgrade: hashing + salting
TODO: remove this page before production deployment!
```

이를 통해 비밀번호가 사용자 이름을 거꾸로 저장한 형태라는 것을 알 수 있었다.

### 취약점

robots.txt와 숨겨진 페이지에 민감한 정보가 노출되었다.

- robots.txt에서 숨겨진 /security 페이지를 노출하였다.
- Base64로 인코딩된 사용자 목록을 주석에 남겨 계정 정보를 노출하였다.
- /security 페이지에서 비밀번호 생성 규칙을 그대로 공개하였다.

공격자는 이러한 정보를 조합하여 별도의 공격 없이 관리자 계정의 비밀번호를 추론할 수 있었다.

### 익스플로잇

1. robots.txt 확인
2. Base64 문자열 디코딩
3. /security 페이지 확인
4. 관리자 계정 비밀번호 추론
```
Username : admin
Password : nimda
```
5. 관리자 계정으로 로그인하여 플래그를 획득하였다.


## 플래그

```
flag{REDACTED}
```

## 배운 점

- robots.txt라는 파일의 존재와 역할을 처음 알게 되었다.