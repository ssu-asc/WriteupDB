---
ctf_name: "Dreamhack Wargame"
challenge_name: "Internal-Secret"
category: web
difficulty: hard
author: yeahhbean
date: "2025-12-06"
tags: [SSRF, "URL Parser Confusion", "Blind SQL Injection", "Allowlist Bypass"]
---

## 개요

'web' (외부 노출, '/fetch') -> 'redirector' -> 'internalapi' (사설망) 3단 구조의
SSRF 챌린지. 'web'은 요청 URL의 host를 'example.com'으로만 제한하지만,
검증에 쓰는 파서('urllib.parse')와 실제 요청에 쓰는 파서('requests'/'urllib3')가
서로 다른 결과를 내는 지점\*\*을 이용해 우회한다. 이후 내부 admin 엔드포인트에서
받아온 flag는 'ADMIN_TOKEN' 없이는 볼 수 없게 막혀 있는데, 이 토큰 체크를
완전히 우회할 수 있는 '/audit' 엔드포인트의 blind SQL Injection을 체이닝해서
최종적으로 flag를 뽑아낸다.

## 구조 분석

- 'web:8080' (외부 노출)
  - 'POST /fetch': 'url' 파라미터를 받아 'host_allowed()'로 검증 후 job으로 큐잉, 별도 스레드가 'requests.get(url, allow_redirects=True)'로 실제 요청 수행, 결과를 sqlite 'jobs.result'에 저장
  - 'GET /result/<job_id>': 'X-Admin-Token' 헤더가 'ADMIN_TOKEN'과 일치해야 결과 열람 가능 (토큰은 기동 시 'os.urandom(32).hex()'로 생성, 어디에도 노출 안 됨)
  - 'GET /audit': 최근 audit 로그 80건을 'order' 파라미터로 정렬해 반환 — 'order' 값이 그대로 f-string에 삽입됨
- 'redirector:8081' (내부망 전용): 'GET /redir?to=<url>' — 'to'로 서버사이드 요청을 대신 보내주고, 이때 'X-Client-IP: 127.0.0.1' 헤더를 항상 붙여서 보냄
- 'internalapi:8081' (내부망 전용): 'GET /admin/flag' — 요청 헤더의 'X-Client-IP'가 '127.0.0.1'이어야 flag 반환

## 취약점 1 — SSRF 필터 우회 (Parser Differential)

'web.py'의 검증 로직:

'''python
def host_allowed(parsed):
host = parsed.hostname or ""
return host == ALLOWED_HOST # "example.com"

parsed = urlparse(unquote(url))
if not host_allowed(parsed):
return 403
'''

문제는 실제 요청이 검증에 쓰인 'parsed'가 아니라 원본 문자열 'url' 그대로
'requests.get(url)'에 들어간다는 점. 'requests'는 내부적으로 'urllib3'의
자체 URL 파서를 쓰는데, 이건 **퍼센트 인코딩을 미리 디코딩하지 않고 원본
문자열의 리터럴 '@', '#' 등을 기준으로 authority를 분리**한다. 반면 검증 로직은
'unquote()'를 먼저 적용한 뒤 stdlib 'urlparse'로 파싱한다. 이 둘의 차이를 이용:

'''
http://example.com%23@redirector:8081/redir?to=<internal target, url-encoded>
'''

- 검증 경로: 'unquote()' -> '%23' -> '#' -> 'urlparse'가 '#' 이후를 fragment로 취급
  -> 'hostname == "example.com"' -> **통과**
- 실제 요청 경로: 'requests'/'urllib3'는 '%23'을 디코딩하지 않으므로 리터럴 '@'가
  그대로 userinfo 구분자로 작동 -> 'userinfo=example.com%23', 'host=redirector'
  -> **실제 커넥션은 'redirector:8081'로 감**

로컬에서 동일한 'requests'/'urllib3' 조합(2.33.1 / 2.6.3)으로 wire-encoding까지
포함해 재현 검증 완료 (form POST 인코딩 -> werkzeug 단일 디코딩 -> 체크용
이중 unquote 차이까지 전부 일치).

이 payload로 'redirector'의 '/redir?to=http://internalapi:8081/admin/flag'를
호출시키면, 'redirector'가 'X-Client-IP: 127.0.0.1'을 스푸핑해서 대신
'internalapi'를 호출해주고, flag JSON을 그대로 프록시해서 'jobs.result'에
저장된다.

## 취약점 2 — '/audit' Blind Boolean-based SQL Injection

'''python
order = request.args.get('order', 'id').strip()
if not order.startswith('id') and not order.startswith('t'):
return 400
cur.execute(f"SELECT ev, job, info, t FROM audit ORDER BY {order} DESC LIMIT 80")
'''

'startswith('id')'/'startswith('t')' 체크는 접두사만 확인하므로 뒤에 임의
표현식을 붙이는 걸 막지 못한다. 'sqlite3' 드라이버가 stacked query는 막아주지만,
**ORDER BY 절 안의 scalar subquery**는 여전히 허용된다는 점을 이용해 blind
boolean oracle을 구성:

'''
order = (CASE WHEN <조건> THEN t ELSE -t END)
'''

앱이 뒤에 자동으로 'DESC'를 붙이고, 응답 직전에 'rows[::-1]'로 한 번 더
뒤집기 때문에:

- 조건이 참이면 최종 응답은 't' 오름차순
- 조건이 거짓이면 't' 내림차순

으로 **전체 목록의 정렬 방향이 통째로 뒤집혀서** 응답 JSON의 첫/마지막
원소만 비교해도 참/거짓을 명확히 구분할 수 있다. 'audit'과 'jobs'는 같은
sqlite 파일에 있으므로, 이 오라클로 'jobs.result' (= 방금 SSRF로 받아온
flag 응답)를 'ADMIN_TOKEN' 없이 바이트 단위로 뽑아낼 수 있다:

'''sql
(SELECT length(result) FROM jobs WHERE id='<job_id>') > N -- 길이 이진탐색
(SELECT unicode(substr(result,N,1)) FROM jobs WHERE id='<job_id>') > N -- 문자 이진탐색
'''

문자당 약 7회 요청(ASCII 32~126 이진탐색)으로 전체 'result' 문자열을 복원.

## Exploit

'solve.py' 참고 ('trigger_ssrf' -> SSRF 체인으로 flag를 'jobs.result'에 적재
-> 'get_length'/'get_char'로 blind SQLi 이진탐색 -> 'DH{...}' 패턴 추출).

'''bash
python3 solve.py http://<target-host>:<port>
'''

## 교훈

- 검증에 쓰는 파서와 실제 동작에 쓰는 파서가 다르면 그 차이 자체가 취약점.
  'urllib.parse'와 'requests'/'urllib3'는 percent-encoding, '@'/'#' 처리에서
  서로 다르게 동작하므로, 같은 URL 문자열이라도 "검증됐다"와 "실제로 요청한
  곳"이 달라질 수 있다. 검증과 요청은 **반드시 같은 파서가 정규화한 동일한
  값**을 대상으로 해야 한다.
- 인증(ADMIN_TOKEN)이 막고 있는 경로가 있어도, 같은 DB를 공유하는 다른
  인증 없는 엔드포인트에 인젝션 지점이 있으면 인증 우회가 아니라 아예
  다른 채널로 데이터가 새어나갈 수 있다.
- f-string으로 SQL을 조립할 때 'startswith()' 같은 접두사 검증은 사실상
  아무 방어도 되지 않는다.

Flag: 'DH{...}'
