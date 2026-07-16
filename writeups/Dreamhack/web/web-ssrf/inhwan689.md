---
ctf_name: "Dreamhack"
challenge_name: "web-ssrf"
category: "web"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "inhwan689"
date: "2020-06-15"
points: 0
tags: [ssrf, filter-bypass, ffuf]
---

# web-ssrf

## 문제 설명

> 이미지 뷰어 기능이 있는 웹 서비스. 사용자가 입력한 URL을 서버가 대신 가져와 이미지로 보여준다. 외부에서 직접 접근할 수 없는 내부 파일 서버의 `flag.txt`를 읽어야 한다.

- 접속 정보: `http://host3.dreamhack.games:PORT/`
- 화이트박스 문제

## 풀이

### 분석

서버 안에 웹서버가 2개 돌고 있다.

1. Flask (@app.route) 정의된 라우트만 응답. flag.txt는 안 내보냄
2. SimpleHTTPRequestHandler 1500~1800 랜덤, 자기 디렉터리(/app)의 파일을 통째로 서빙 --> flag.txt를 웹으로 노출

/img_viewer는 사용자가 준 url을 서버가 대신 requests.get() 하는 기능 --> SSRF


### 취약점

1. SSRF

### 익스플로잇

#### 1. 이미지 뷰어 동작 확인

/img_viewer에 이미지가 아닌 일반 URL을 제출하면 error 이미지가 반환된다. 외부 URL은 채점 서버가 외부망으로 나가지 못해 timeout 처리되며, 이로써 접근 가능한 대상은 내부임을 알 수 있다.

#### 2. 목표 서버 식별

소스에서 flag를 웹으로 노출하는 서버는 Flask(8000)가 아니라 127.0.0.1의 랜덤 포트(1500~1800)에 뜬 SimpleHTTPRequestHandler임을 확인한다. 이 서버는 /app 디렉터리를 통째로 서빙하므로 flag.txt가 노출된다.

```
http://127.0.0.1:<1500-1800>/flag.txt   <-- 목표
```

#### 3. 검증 로직 확인

/img_viewer의 URL 필터는 다음과 같이 동작한다.

- /로 시작하는 입력은 http://localhost:8000을 강제로 붙인다.
- netloc에 문자열 localhost 또는 127.0.0.1이 포함되면 차단한다.
- 그 외에는 서버가 requests.get()으로 직접 요청한다.

#### 4. 정수 IP로 필터 우회

127.0.0.1을 32비트 정수 2130706433으로 표기한다. netloc에 금지 문자열이 없어 필터를 통과하지만, OS의 주소 변환은 이를 동일하게 127.0.0.1로 해석하므로 실제 요청은 내부 서버로 향한다.

```text
http://2130706433:1724/flag.txt
```

#### 5. 랜덤 포트 브루트포스

내부 서버 포트는 배포마다 1500~1800(301개) 중 하나로 무작위다. 포트가 틀리면 연결 실패로 error 이미지, 맞으면 flag.txt가 반환되므로 응답 크기로 정답 포트를 특정한다.

```bash
seq 1500 1800 > /tmp/ports.txt
ffuf -w /tmp/ports.txt:FUZZ \
  -u http://host3.dreamhack.games:PORT/img_viewer \
  -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'url=http://2130706433:FUZZ/flag.txt' -mc all
```

크기가 튀는 응답 하나가 정답 포트다.

#### 6. 플래그 추출

응답은 대상 URL의 내용을 <img src="data:image/png;base64, ...">에 담아 반환한다. flag는 텍스트라 화면엔 이미지로 안 보이지만, 개발자도구로 이미지의 값을 가져와 base64 디코드 하면 플래그가 보인다

## 플래그

```
DH{43dd2189056475a7f3bd11456a17ad71}
```

## 배운 점

- SSRF의 개념: "서버가 사용자 대신 요청을 보내는 기능"은 곧 내부망 접근 권한을 빌려주는 것.
- 퍼징의 개념과 도구 (ffuf)