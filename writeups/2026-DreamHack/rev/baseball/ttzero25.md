---
ctf_name: "DreamHack Wargame"
challenge_name: "baseball"
category: "rev"
difficulty: "easy"
author: "ttzero25"
date: "2026-07-07"
tags: [base64, custom-alphabet, known-plaintext]
---

# baseball

## 문제 설명

> 주어진 인코더 바이너리와 몇 개의 입출력 파일로부터 플래그를 복구하라.

- 제공 파일: `baseball`(ELF 64-bit), `text_in.txt`, `text_out.txt`, `flag_out.txt`

## 풀이

### 분석

먼저 바이너리의 기본 정보와 사용법을 확인한다.

```console
$ file baseball
baseball: ELF 64-bit LSB pie executable, x86-64, ... stripped

$ ./baseball
Usage : ./baseball <table filename> <input filename>
```

`baseball`은 **table 파일**과 **input 파일**을 인자로 받는 인코더다. 이름(`baseball` = `base` + ...)과 입출력 길이 관계를 보면 Base64 인코더임을 추측할 수 있다.

`text_in.txt`는 149바이트, `text_out.txt`는 200자다. Base64는 3바이트를 4자로 인코딩하므로:

```
ceil(149 / 3) * 4 = 50 * 4 = 200   # text_out 길이와 정확히 일치
149 mod 3 = 2  ->  패딩 '=' 1개     # text_out 은 '=' 1개로 끝남
```

즉 이 바이너리는 **평범한 Base64**이되, 인자로 주어지는 `table`(64자 문자열)이 곧 **커스텀 알파벳**인 구조다. 표준 알파벳 `A-Za-z0-9+/` 대신 임의로 뒤섞인 순열을 쓴다.

우리에게 `table` 파일은 주어지지 않지만, **알려진 평문/암호문 쌍**(`text_in.txt` → `text_out.txt`)이 있으므로 알파벳 순열을 역으로 복원할 수 있다.

### 취약점

커스텀 Base64는 **알파벳을 비밀로 유지할 때만** 의미가 있다. 그런데 이 문제는 동일한 알파벳으로 인코딩된 **알려진 평문 샘플**(`text_in`/`text_out`)을 함께 제공한다.

표준 Base64로 인코딩한 `text_in`의 각 문자를, 같은 위치의 `text_out` 문자와 정렬하면 `표준_알파벳_문자 ↔ 커스텀_알파벳_문자` 대응표가 그대로 드러난다. 이것이 전형적인 **known-plaintext(알려진 평문) 공격**이며, 복원한 대응표를 `flag_out.txt`에 적용하면 플래그가 나온다.

이번 샘플만으로 64개 중 53개 위치가 확정되는데, 이 53개가 `flag_out.txt`에 등장하는 모든 문자를 커버하므로 플래그 복원에는 충분하다.

### 익스플로잇

```python
#!/usr/bin/env python3
import base64

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

pt = open("text_in.txt", "rb").read()
ct = open("text_out.txt").read().strip()
flag_ct = open("flag_out.txt").read().strip()

# 알려진 평문을 표준 Base64로 인코딩
b64 = base64.b64encode(pt).decode()
assert len(b64) == len(ct)

# 대응표 복원: 커스텀_문자 -> 6비트 인덱스(표준 알파벳 위치)
inv = {}
for s, c in zip(b64, ct):
    if s == "=" or c == "=":
        continue
    inv[c] = STD.index(s)

# 복원한 알파벳으로 플래그 디코딩
bits = "".join(format(inv[ch], "06b") for ch in flag_ct if ch != "=")
out = bytearray(int(bits[i:i+8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))

print("FLAG: DH{%s}" % out.decode())
```

실행 결과:

```console
$ python3 solve.py
recovered alphabet entries: 53
FLAG: DH{Did you know how base64 works}
```

## 플래그

```
DH{Did you know how base64 works}
```

## 배운 점

- 입력·출력 **길이 관계**(`ceil(n/3)*4`, 패딩 개수)만으로도 인코딩이 Base64 계열인지 빠르게 판별할 수 있다.
- 커스텀 알파벳 Base64는 알파벳을 비밀로 지킬 때만 안전하다. **알려진 평문 샘플이 하나라도 노출되면** 알파벳 순열이 그대로 복원되어 방어 효과가 사라진다.
- 전체 64자를 복원할 필요 없이, **타깃 암호문에 등장하는 문자**만 매핑되면 복호화가 가능하다.
