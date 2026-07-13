---
ctf_name: "LYKNCTF"
challenge_name: "LYKN Corp"
category: "web"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "inhwan689"
date: "2026-07-06"
points: 100
tags: [credential-reuse]
---

# 문제명 - LYKN Corp

## 문제 설명

> LYKN Corp - Onboarding portal for new employees. The system looks secure, but is it? Let's find the secrets hidden inside!

- 문제 URL : `http://<instance>.51.79.140.18.nip.io:8080` / 파일 등 접속 정보 : Flask 기반 사내 웹메일 포털

## 풀이

### 분석

robots.txt에 백업 경로가 노출되어 있다.

Disallow: /backup

/backup은 nginx가 403으로 막지만, 대문자 /Backup/으로 우회가 가능하다. 여기서 계정 정보가 담긴 파일을 얻는다.

GET /Backup/credentials.txt
--> tuan.nguyen / Welcome123!

로그인하면 inbox / sent / compose로 구성된 웹메일이 보이고, 받은 메일의 발신자가 minh.le@lykn.local 형식으로 나와 계정·도메인 규칙을 알 수 있다. /admin 페이지는 존재하지만 employee 권한이라 403이 뜬다.

### 취약점

패스워드 재사용 + 평문 크레덴셜 유출

Welcome123!은 신입용 기본 비밀번호다. 다른 직원들이 이걸 바꾸지 않아, 유출된 username에 그대로 재사용해 로그인할 수 있다. 게다가 관리자가 다른 직원에게 보낸 메일 본문에 관리자 크레덴셜이 평문으로 들어 있다.

### 익스플로잇

기본 비번 재사용 → 다른 직원 계정 로그인

Welcome123!을 발견한 다른 계정(minh.le)에 그대로 시도하면 로그인된다.

이후 minh의 받은 편지함에 admin계정의 아이디, 비밀번호가 있고, 이 계정으로 접속하면 페이지에 flag가 노출되어있다.

## 플래그

```
LYKNCTF{REDACTED}
```

## 배운 점

- 주어진 내 계정만 파지 말고 다른 사용자 계정으로 이동할 생각을 해야 한다.
- 브루트포스가 rockyou로도 안되면 이 길이 아니다라고 생각하고 다른 해결 방안을 빠르게 찾아봐야 한다.
