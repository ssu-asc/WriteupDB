---
ctf_name: "No Hack No CTF 2026"
challenge_name: "newbie-crypto"
category: "crypto"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "minyoung13"
date: "2026-07-05"
points: 100
tags: [AES, XOR]
---

# newbie-crypto

## 문제 설명

- 첨부파일 : chall.py, output.txt, public.txt

## 풀이

### 분석

1. 해당 문제는 public.txt에 공개된 값을 활용하여 chall.py 파일로 암호화하고(guest ticket과 admin ticket을 생성) 그 결과를 output.txt에 저장한 것이다.
2. chall.py 파일에서는 랜덤한 16바이트 키와 NONCE = b"ticket42" 값을 사용한다.
3. ticket을 `json.dumps(ticket, separators=(",", ":")).encode()` 방식으로 JSON 바이트 문자열로 변환한 후 AES CTR Mode로 암호화한다.
4. AES CTR Mode는 내부적으로 keystream을 생성한 뒤, 평문과 XOR하여 암호문을 만든다.
즉, `ciphertext = plaintext XOR keystream` 이므로, `plaintext XOR ciphertext`를 통해 keystream을 복구할 수 있다. 
5. 문제에서는 guest ticket의 name, seat 값, 그리고 암호문이 공개되어 있으므로, guest ticket 평문과 암호문을 XOR하여 keystream을 복구하고, 그 값으로 admin_cipher에 XOR하여 flag를 획득할 수 있다.

### 취약점

모든 암호화에서 같은 키와 b"ticket42"라는 고정된 nonce 값을 사용한다.
AES CTR Mode에서는 같은 key와 nonce를 재사용하면 같은 keystream이 생성된다. 따라서 하나의 평문-암호문 쌍만 알고 있어도 keystream을 복구할 수 있고, 같은 keystream으로 암호화된 다른 암호문도 복호화할 수 있다.
이 문제에서는 guest ticket의 평문을 알 수 있으므로 keystream을 복구한 뒤, admin_cipher를 XOR하여 flag가 포함된 admin ticket을 복호화할 수 있다.

### 익스플로잇

1. guest ticket 평문을 만든다.
2. guest ticket 평문과 output.txt의 guest cipher를 XOR하여 keystream을 복구한다.
3. 가장 긴 guest ticket에서 얻은 keystream을 사용한다. (평문 길이만큼 keystream이 사용되므로 가장 긴 guest ticket에서 얻은 keystream을 사용한다.)
4. admin_cipher와 keystream을 XOR하여 admin ticket 평문을 복구하고, admin ticket 안의 flag 값을 확인한다.

```python
import json

ATTENDEES = [
    ("hsuan0223x", "H-0223"),
    ("NHNC", "T-0704"),
    (
        "this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read",
        "N-0705",
    ),
    ("AI_WILL_SLOP", "C-114514"),
]

guest_ciphers = [
    "c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2c0890bc6bf92f2a5dd1b971c73dd03b6593f0142f053b6bb64ac86d7a1d511690f30d81ca56ff87c98c701f3c0129f9bce7912924609baf0d0baae3989b7530f77542e69116cc",
    "c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2c0890bc6bf92f2a5dd1b971c73dd01d5ea8d25833157a3daf1cc6752b2c1d5285f91bebcb44a3da8ecb7e07700b33f6f1a49338226fd4a1420da9f5d0836a60e1",
    "c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2c0890bc6bf92f2a5dd1b971c73dd0277e8fe2257c5f683491068b3b56165507d6965dac860292c79fcf3862200b3cf8c1afd62d2e5586b34c1b9df4dd8d7e1dee634bedbe46d4ce749d41ce8f61118d060becd997309da64e9e5799b1625d333bd783837104cf82f6b1da7a7d613364771111a4688f1d6002b454315f2041d6a77749f11b19",
    "c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2c0890bc6bf92f2a5dd1b971c73dd0125fb9c633537b560b8227b46d255a4307d3bd0df3c525e084cb9a690c664c71bef0b2c7296830d6b34315adff98987227bc7145fb8a47d9c060e04e",
]

admin_cipher = "c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2a1998a671f92f2a5dd1b971c73dd03c6481f014764d6c2aec44c63c6c19444088eb7d86a832ef99d8c03349374c67beeeafda23386380af0d1ea1e5dd9f6962fb744be79551d58d3ce055c78f626cc54124c0c8a62e9ff51eed1ed9ad361e6332c1a09b1e069787a1f19c4b7c2620753f6c06f93595162e0bfe4c"

def encode_ticket(ticket):
    return json.dumps(ticket, separators=(",", ":")).encode()

def make_guest_ticket(name, seat):
    return encode_ticket({
        "event": "modern-crypto-101",
        "role": "guest",
        "name": name,
        "seat": seat,
        "note": "enjoy the workshop",
    })

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

keystream = b""

for (name, seat), cipher_hex in zip(ATTENDEES, guest_ciphers):
    plaintext = make_guest_ticket(name, seat)
    ciphertext = bytes.fromhex(cipher_hex)

    current_keystream = xor_bytes(plaintext, ciphertext)

    if len(current_keystream) > len(keystream):
        keystream = current_keystream

admin_plain = xor_bytes(bytes.fromhex(admin_cipher), keystream)

print(admin_plain.decode())
```

## 플래그

```
NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}
```

## 배운 점

- AES CTR Mode는 nonce와 블록을 암호화할 때마다 1씩 증가하는 counter를 AES로 암호화하여 keystream을 생성하고, 해당 keystream과 평문 블록을 XOR하여 암호문 블록을 만든다. 따라서 같은 key와 nonce를 재사용하면 같은 keystream이 다시 생성된다. 이 문제에서는 매번 `AES.new(KEY, AES.MODE_CTR, nonce=b"ticket42")`를 호출하므로 guest와 admin의 첫 번째 바이트, 두 번째 바이트, 세 번째 바이트...에 사용된 keystream이 전부 같아진다.