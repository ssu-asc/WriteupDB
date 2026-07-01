---
ctf_name: "SekaiCTF 2026"
challenge_name: "migurimental"
category: "web"
difficulty: "insane"
author: "oscarjhk"
date: "2026-06-29"
tags: ["Next.js", "Middleware", "Request Normalization", "Cookie Parsing", "0day"]
---

# migurimental

## 문제 설명

> Poor migu lost her leek 🥀🥀

문제는 두 개의 Next.js 서비스로 구성되어 있다.
각 서비스는 같은 `/flag.txt`를 읽지만, 서로 다른 절반만 출력한다.

```text
https://migurimental.chals.sekai.team
https://migurimental-2.chals.sekai.team
```

문제 note에는 실제 0day를 사용하는 챌린지이며, 취약점이 패치되기 전까지 세부 내용을 공개하지 말아 달라는 안내가 있었다.
따라서 이 writeup에서는 전체 풀이 흐름과 원인만 정리하고, 재현 가능한 framework payload 문자열은 패치 전까지 생략한다.

## 풀이

### 분석

첨부된 소스에는 `apps/backstage1`, `apps/backstage2` 두 개의 Next.js 앱이 있고, 둘 다 `next@16.2.9`를 사용한다.
nginx는 각각 내부 포트 `3001`, `3002`로 프록시한다.

첫 번째 앱은 회원가입과 로그인 기능을 제공한다.
회원가입한 사용자는 `REGULAR` 등급으로 생성되고, 기본으로 들어 있는 `miku` 사용자만 `VIP` 등급이다.

`/access-card`는 사용자의 access card와 `ticket_uuid` QR 코드를 렌더링한다.
이 페이지는 middleware에서 다음 조건을 검사한다.

```javascript
if (request.nextUrl.pathname === '/access-card') {
  const checkedId = request.nextUrl.searchParams.get('id')

  if (checkedId !== session.sub) {
    return deny(request)
  }
}
```

`/backroom`은 첫 번째 flag half를 읽는다.
middleware는 JWT 안의 `ticketUuid`와 cookie의 `ticket_uuid`가 일치하는지만 확인한다.
하지만 실제 SSR 페이지에서는 cookie의 `ticket_uuid`로 DB를 다시 조회하고, 그 사용자의 id가 `1`인지 확인한다.

```javascript
const ticketUser = await findByTicketUuid(req.cookies.ticket_uuid || '')

if (ticketUser?.id !== 1) {
  res.statusCode = 403
  return { props: { backstageNote: '', denied: true } }
}
```

즉 첫 번째 앱의 목표는 다음 두 단계다.

1. 일반 계정 세션으로 `miku`의 access card를 읽어 VIP `ticket_uuid`를 얻는다.
2. middleware는 일반 계정으로 통과시키고, SSR은 VIP `ticket_uuid`를 보게 만들어 `/backroom`을 렌더링한다.

두 번째 앱은 더 단순하다.
`/`에서 두 번째 flag half를 SSR로 출력하지만, middleware가 `x-real-migu` 헤더 값을 검사한다.
nginx가 이 헤더를 `$remote_addr`로 덮어쓰므로 클라이언트가 직접 `1.3.3.7`을 넣는 방식은 통하지 않는다.

```javascript
const remoteAddress = request.headers.get('x-real-migu') || ''

if (remoteAddress !== '1.3.3.7') {
  return NextResponse.redirect(new URL('/rejected', request.url), 302)
}
```

### 취약점

이 문제는 애플리케이션 로직 자체의 단순 실수가 아니라, Next.js의 middleware 처리와 Pages Router SSR 처리 사이의 request normalization 차이를 이용한다.

첫 번째 앱의 `/access-card`에서는 middleware가 보는 query와 SSR이 받는 query가 서로 다르게 정규화되는 케이스가 있었다.
이를 이용하면 middleware에는 내 일반 계정 id가 보이게 하고, SSR에는 `id=1`이 보이게 할 수 있다.
그 결과 일반 계정 세션으로 VIP 사용자인 `miku`의 access card를 렌더링할 수 있고, QR 코드에 들어 있는 VIP `ticket_uuid`를 얻을 수 있다.

첫 번째 앱의 `/backroom`에서는 Edge middleware의 cookie parser와 Node SSR의 `req.cookies`가 중복 cookie를 처리하는 방식이 달랐다.
같은 이름의 cookie가 여러 번 들어 있을 때 middleware와 SSR이 선택하는 값이 갈라졌고, 이 차이로 middleware는 일반 계정의 ticket을 확인하게 하면서 SSR은 VIP ticket을 조회하게 만들 수 있었다.

두 번째 앱에서는 `assetPrefix: '/cdn'` 설정으로 인해 static/data route rewrite가 생성된다.
middleware matcher가 보는 path와 실제 SSR로 이어지는 Pages Router data route 처리 순서가 어긋나면서, middleware가 `/` 보호 로직을 실행하지 않은 상태로 `/`의 `getServerSideProps`가 렌더링되는 경로가 존재했다.

세 취약점 모두 Next.js 내부 request normalization과 middleware 경계에서 발생한다.
문제 note에 따라, 패치 전까지는 정확한 query key, cookie layout, data route path는 공개하지 않는다.

### 익스플로잇

전체 exploit 흐름은 다음과 같다.

1. 첫 번째 앱에서 임의의 일반 계정을 등록한다.
2. 일반 계정 세션을 유지한 채, middleware와 SSR의 query 해석 차이를 이용해 `miku`의 `/access-card`를 렌더링한다.
3. access card 안의 QR 코드 이미지에서 VIP `ticket_uuid`를 디코딩한다.
4. 중복 cookie 처리 차이를 이용해 `/backroom` 요청을 보낸다.
5. 첫 번째 flag half를 `__NEXT_DATA__`의 `pageProps.backstageNote`에서 읽는다.
6. 두 번째 앱에서 public page를 통해 build id를 확인한다.
7. middleware matcher와 data route rewrite 순서 차이를 이용해 두 번째 flag half를 렌더링한다.
8. 두 half를 이어 붙여 최종 flag를 얻는다.

실제 exploit 스크립트는 `requests`로 회원가입과 SSR 요청을 수행하고, QR 코드는 OpenCV의 `QRCodeDetector`로 디코딩했다.
첫 번째 half는 `/backroom` HTML 안의 `__NEXT_DATA__`에서 추출했고, 두 번째 half도 SSR 결과의 `__NEXT_DATA__`에서 추출했다.

공격이 성공하면 다음과 같은 형태로 두 조각이 출력된다.

```text
first_half  = SEKAI{..._7h3_
second_half = c0nc3r7_...}
```

## 플래그

```text
SEKAI{REDACTED}
```

## 배운 점

Next.js middleware는 보안 경계처럼 보이지만, 실제 렌더링 단계와 완전히 같은 request representation을 공유한다고 가정하면 안 된다.
Edge runtime에서 보는 `NextRequest`, 라우터의 data route normalization, Pages Router의 `getServerSideProps` 입력, Node cookie parser가 모두 조금씩 다른 계층에 있기 때문이다.

특히 middleware에서 접근 제어를 수행할 때는 query, cookie, rewritten path처럼 framework가 내부적으로 재해석할 수 있는 값에 민감한 결정을 맡기면 위험하다.
가능하면 최종 handler에서 같은 representation으로 권한을 다시 확인하고, 중복 cookie나 internal query parameter처럼 애매한 입력은 명시적으로 거부하는 방어가 필요하다.
