---
ctf_name: "2026-D3CTF"
challenge_name: "Proxy Port"
category: "misc"
difficulty: "medium"
author: "vestman828"
date: "2026-07-26"
tags: [misc]
---

# Proxy Port

## 문제 설명

> 2026-D3CTF의 Proxy Port 문제입니다. Misc입니다.

## 풀이

### 분석

문제는 포워딩 동작을 탐색하는 TLS 서비스와 정답을 제출하는 TLS 서비스로 구성됩니다. 먼저 SHA-256 PoW를 통과한 뒤, 총 20라운드에서 현재 포워딩 구현체가 `gost`인지 `frp`인지 구분해야 합니다. 한 라운드에서 허용되는 탐색 횟수는 5회입니다.

PoW 조건은 서버가 준 32바이트 ASCII prefix 뒤에 suffix를 붙였을 때 SHA-256 해시의 앞 26비트가 0이 되는 값을 찾는 것입니다. suffix를 8바이트로 고정하면 메시지 길이가 40바이트이므로 패딩까지 SHA-256 블록 하나에 들어갑니다. 각 후보마다 전체 해시 API를 호출하는 대신 suffix 부분만 바꾼 블록에 `SHA256_Transform()`을 한 번 적용하고, CPU 코어별로 탐색 범위를 나누어 약 1초 안팎으로 해결했습니다.

구현체를 구분하기 위해 여러 입력과 연결 종료 방식을 시험한 결과, `X` 한 바이트를 보낸 직후 쓰기 방향만 half-close했을 때 안정적인 차이가 발생했습니다.

```python
s.sendall(b"X")
s.shutdown(socket.SHUT_WR)
```

`shutdown(SHUT_WR)`는 더 이상 데이터를 보내지 않겠다는 FIN만 전송하므로 반대 방향 응답은 계속 읽을 수 있습니다. 이때 관측되는 TLS 레코드 길이는 다음과 같았습니다.

- `gost`: 149바이트
- `frp`: 24바이트

`gost`는 `5 + 0x78`바이트 application record와 `5 + 0x13`바이트 close record를 보냈고, `frp`는 close record 24바이트만 보냈습니다. 따라서 수신 길이가 24보다 크면 `gost`, 그렇지 않으면 `frp`로 분류할 수 있습니다.

네트워크 문제로 가끔 0바이트가 수신되었기 때문에, 이 경우에만 최대 3번 다시 탐색하도록 했습니다. 따라서 라운드당 5회 제한도 넘지 않습니다.

### 익스플로잇

```python
import socket
import ssl

def probe(host, port=443):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port)) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall(b"X")
            s.shutdown(socket.SHUT_WR)

            data = bytearray()
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return bytes(data)

data = probe(FORWARD_HOST)
attempts = 1

while len(data) == 0 and attempts < 3:
    data = probe(FORWARD_HOST)
    attempts += 1

answer = "gost" if len(data) > 24 else "frp"
control.sendall(f"answer {answer}\n".encode())
```

전체 자동화는 다음 순서로 진행합니다.

1. 정답 제출 서비스에 TLS로 접속합니다.
2. prefix를 읽고 `pow_fast2`로 suffix를 구합니다.
3. `pow <suffix>`를 제출합니다.
4. 매 라운드마다 포워딩 서비스에 연결해 1바이트와 FIN을 보냅니다.
5. 수신 길이로 구현체를 분류해 답을 제출합니다.

```bash
gcc -O3 -pthread pow_fast2.c -lcrypto -o pow_fast2
python3 solve_final.py
```

## 플래그

```text
d3ctf{diVe-1nto-thE-I0wer_NetWoRK-l4YER-wil1_YOu_5ee_the_truth0}
```

## 배운 점

프록시 구현체를 구분할 때 애플리케이션 수준 응답만 볼 필요는 없습니다. half-close처럼 경계 상황을 만들고 TLS 레코드의 종류와 길이를 비교하면 구현체별 연결 종료 처리의 차이가 강한 fingerprint가 될 수 있습니다.
