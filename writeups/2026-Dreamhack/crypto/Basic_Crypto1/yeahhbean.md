---
ctf_name: "Dreamhack Wargame"
challenge_name: "Basic_Crypto1"
category: "crypto"
difficulty: "easy"
author: "yeahhbean"
date: "2026-06-28"
points: 17
tags: [Caesar Cipher, Classical Cipher, Brute Force, Substitution Cipher]
---

# Basic_Crypto1

## 문제 설명

> Basic*Crpyto (Roman emperor's cipher)
> FLAG FORMAT(A~Z) and empty is `"*"`→`DH{decode_Text}`

- Level 1 / crypto, 17 points
- 첨부: `encode.txt`

```
EDVLF FUBSWR GUHDPKDFN
```

문제 설명에서 "Roman emperor's cipher"라는 표현으로 이미 **시저 암호(Caesar Cipher)** 임을 직접 알려준다. 로마 황제(율리우스 카이사르)가 사용한 것으로 알려진 가장 고전적인 단일 치환 암호다.

## 풀이

### 분석

암호문은 알파벳과 공백만으로 구성된 22글자짜리 짧은 문자열이다. 시저 암호는 각 알파벳을 고정된 정수만큼 순환 이동(shift)시켜 만드는 암호로, **키 공간이 25가지(A~Z, shift 0 제외)뿐**이라 별도의 알고리즘적 취약점을 찾을 필요 없이 **전수조사(brute-force)** 로 즉시 풀린다.

### 취약점

고전 치환 암호의 근본적 약점 — 키 공간이 극도로 작다(25). 현대 암호(AES 등)와 달리 계산 복잡도 기반 안전성이 전혀 없어 모든 키를 시도해 보고 사람이 읽을 수 있는 평문이 나오는 지점을 고르면 끝난다.

### 익스플로잇

```python
def caesar_shift(text: str, shift: int) -> str:
    out = []
    for c in text:
        if c.isupper():
            out.append(chr((ord(c) - 65 - shift) % 26 + 65))
        elif c.islower():
            out.append(chr((ord(c) - 97 - shift) % 26 + 97))
        else:
            out.append(c)  # 공백 등 비알파벳은 그대로
    return "".join(out)

ciphertext = "EDVLF FUBSWR GUHDPKDFN"
for key in range(26):
    print(f"key {key:2d}: {caesar_shift(ciphertext, key)}")
```

실행 결과 `key = 3`에서 유일하게 의미가 통하는 문자열이 나온다:

```
key  3: BASIC CRYPTO DREAMHACK
```

문제가 명시한 플래그 포맷 `FLAG FORMAT(A~Z) and empty is "_"` 에 따라 **알파벳은 그대로, 공백은 `_`로 치환**해서 `DH{}`로 감싸면 플래그가 완성된다.

```python
flag_body = caesar_shift(ciphertext, 3).replace(" ", "_")
print(f"DH{{{flag_body}}}")
```

## 플래그

```
DH{BASIC_CRYPTO_DREAMHACK}
```

## 배운 점

- **시저 암호는 키 공간이 25뿐**이라 사람이 눈으로 훑어봐도, 스크립트로 돌려도 즉시 깨진다. 실전에서 단일 치환/이동 암호를 어떤 형태로든(바이트 단위 XOR-add 포함) 쓰면 안 되는 이유가 여기 있다.
- **문제 설명이 곧 알고리즘 힌트**인 경우가 많다 — "Roman emperor's cipher"처럼 별칭이나 은유를 통해 어떤 암호인지 노골적으로 알려주는 초급 문제 패턴을 인식해두면 접근 속도가 빨라진다.
- **플래그 포맷 규칙(공백→`_`)을 문제 설명에서 놓치지 않는 것**도 실수를 줄이는 포인트. 평문을 찾는 것과 그걸 정확한 제출 형식으로 변환하는 것은 별개의 단계다.
