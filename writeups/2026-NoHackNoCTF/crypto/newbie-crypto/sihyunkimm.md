---
ctf_name: "No Hack No CTF 2026"
challenge_name: "newbie-crypto"
category: "crypto"
difficulty: "easy"
author: "sihyunkimm"
date: "2026-07-04"
points: 100
tags: [AES]
---

# newbie-crypto

## 문제 설명

AES-CTR 모드로 여러 참가자의 guest 티켓과 admin 티켓을 암호화한 `chall.py`,
참가자 목록인 `public.txt`, 암호문이 담긴 `output.txt`가 주어진다. admin 티켓에 포함된 플래그를 복구하는 문제이다.

## 풀이

### 분석

티켓은 JSON을 공백 없이 직렬화한 뒤 AES-CTR로 암호화된다.

```python
KEY = get_random_bytes(16)
NONCE = b"ticket42"

def encrypt(ticket):
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.encrypt(ticket).hex()
```

`encrypt()`를 호출할 때마다 CTR cipher 객체를 새로 만들지만, 키와 nonce가 항상 같으므로 카운터의 시작점도 매번 같다. 따라서 모든 티켓에 동일한 키스트림이 사용된다.
CTR 모드의 암호화는 다음과 같다.

```text
C = P XOR KS
```

여기서 평문 `P`와 암호문 `C`를 알고 있다면 키스트림을 복구할 수 있다.

```text
KS = P XOR C
```

### 취약점

취약점은 같은 키에서 nonce를 재사용한 것이다. CTR 모드에서는 nonce와 카운터로 생성한 키스트림을 평문과 XOR하므로, 같은 nonce를 재사용하면 같은 위치의 키스트림도 재사용된다.

guest 티켓은 `chall.py`와 `public.txt`만으로 JSON 평문 전체를 정확히 만들 수 있다.
그중 `guest_cipher_2`는 긴 참가자 이름 때문에 171바이트이고, 160바이트인 `admin_cipher` 전체를 복호화할 수 있다.

### 익스플로잇

세 번째 guest 티켓의 알려진 평문과 암호문을 XOR해 키스트림을 구한 뒤, admin 암호문과 다시 XOR한다.

```python
import json
import re
from pathlib import Path


def encode_ticket(ticket):
    return json.dumps(ticket, separators=(",", ":")).encode()


def read_cipher(output, name):
    match = re.search(rf"^{name} = ([0-9a-f]+)$", output, re.MULTILINE)
    return bytes.fromhex(match.group(1))


name = "this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read"
seat = "N-0705"

guest_plain = encode_ticket(
    {
        "event": "modern-crypto-101",
        "role": "guest",
        "name": name,
        "seat": seat,
        "note": "enjoy the workshop",
    }
)

output = Path("output.txt").read_text(encoding="utf-8")
guest_cipher = read_cipher(output, "guest_cipher_2")
admin_cipher = read_cipher(output, "admin_cipher")

keystream = bytes(p ^ c for p, c in zip(guest_plain, guest_cipher))
admin_plain = bytes(c ^ k for c, k in zip(admin_cipher, keystream))

print(admin_plain.decode())
```

실행 결과 admin 티켓 전체가 복호화된다.

```json
{"event":"modern-crypto-101","role":"admin","name":"organizer","seat":"ROOT","note":"priority access granted","flag":"NHNC{REDACTED}"}
```

## 플래그

```text
NHNC{REDACTED}
```

## 배운 점

- 다른 좀 더 어려운 문제를 풀고 싶었지만 풀지 못해 좀 쉬운 문제를 선택한 점이 아쉬웠다.  
