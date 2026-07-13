---
ctf_name: "LYKNCTF"
challenge_name: "Cr4ck_1"
category: "rev"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "khgkhg05"
date: "2026-07-07"
points:
tags: [PE, x86-64, keygen, anti-debugging, SHA-256, RC4, self-hash]
---

# Cr4ck_1

## 문제 설명

> Windows GUI keygen 프로그램에서 올바른 username과 license key를 찾아 flag를 얻는다.

- 문제 파일: `KeygenMe.exe`
- 파일 형식: PE32+ executable (GUI), x86-64, stripped to external PDB
- 빌드 흔적: MinGW-w64 GCC 15.2.0

## 풀이

### 분석

문자열을 먼저 보면 GUI에 입력해야 하는 값과 성공/실패 메시지를 바로 확인할 수 있다.

```text
Username:
License Key:
Unknown account.
This license desk only serves one client.
Wrong license key for this account.
Keep reversing!
LYKN2026
Access granted!
Flag: %s
L0i_Y3u_Kh0_N0i
```

`Access granted!`, `Wrong license key`, `Unknown account` 문자열의 xref를 따라가면 버튼 핸들러 한 곳에서 대부분의 검증이 이루어진다. 흐름은 다음과 같다.

1. `GetDlgItemTextA()`로 username과 license key를 읽는다.
2. license key의 소문자를 대문자로 바꾼다.
3. PEB와 `NtQueryInformationProcess()`로 anti-debug mask를 만든다.
4. 숨겨진 username을 생성한 뒤 입력 username과 비교한다.
5. username과 anti-debug mask로 license key를 생성해 입력 license와 비교한다.
6. license가 맞으면 `.text` section SHA-256, username, license, anti-debug mask를 섞어 flag ciphertext를 복호화한다.

anti-debug mask는 다음 네 조건을 bit로 합친 값이다.

| bit | 조건 |
|-----|------|
| `1` | `PEB.BeingDebugged != 0` |
| `2` | `PEB.NtGlobalFlag & 0x70 != 0` |
| `4` | `NtQueryInformationProcess(ProcessDebugPort)` 결과가 존재 |
| `8` | `NtQueryInformationProcess(ProcessDebugFlags)`가 디버깅 상태를 가리킴 |

정상 실행에서는 이 값이 `0`이다. 이 mask가 license 생성과 flag 복호화 seed에 모두 들어가므로, 디버거가 붙은 상태에서 분석한 값을 그대로 쓰면 license나 flag 검증이 어긋난다.

### 숨겨진 username

프로그램은 먼저 256바이트 S-box를 만든다. 초기값은 `S[i] = i`이고, `S[0]`과 `S[0x4c]`를 먼저 swap한 뒤 `"L0i_Y3u_Kh0_N0i"`를 key로 KSA와 비슷한 루프를 돈다.

```python
def init_sbox():
    key = b"L0i_Y3u_Kh0_N0i"
    sbox = list(range(256))
    j = (sbox[0] + 0x4c) & 0xff
    sbox[0], sbox[j] = sbox[j], sbox[0]

    for i in range(1, 256):
        x = sbox[i]
        j = (x + key[i % 15] + j) & 0xff
        sbox[i], sbox[j] = sbox[j], x

    return sbox
```

username 생성 루틴은 이 S-box의 일부 byte와 `.rdata` 상수를 XOR한다. 이 과정을 재구현하면 다음 문자열이 나온다.

```text
th3_LYKN_v3nd0r
```

입력 username이 이 값과 다르면 `Unknown account.` 경로로 빠진다.

### License key

license 생성 함수는 username byte를 세 번 순회한다. 각 순회마다 S-box lookup 값과 `rol32()`를 이용해 4개의 32비트 상태값을 갱신한다. 초기 상태에는 anti-debug mask가 들어간다.

```python
r8 = (debug_mask * 0x01010101) ^ 0x4c594b4e
r9 = 0xae054fb9
r11 = 0x43544632
edi = 0xa5a5f00d
```

정상 실행 기준 `debug_mask = 0`으로 계산하면 마지막 상태값은 다음과 같다.

```text
r8  = 0x72111d0c
r11 = 0xcd964ac8
r9  = 0x38f680fb
edi = 0x26a24cdd
```

이 값을 16비트 단위로 접어 5개의 word를 만들고, 각 word를 대문자 hex 네 자리로 출력한다.

```text
7211-57C4-CD96-CC26-5B67
```

license 입력은 비교 전에 대문자로 바뀌므로 대소문자 자체는 중요하지 않다.

### Flag 복호화

license가 맞아도 바로 flag가 출력되는 것은 아니다. 프로그램은 자기 자신의 `.text` section을 SHA-256으로 해시한다.

```text
SHA256(.text) = 540a6fe0dfa677f2a7b1603fd0db282a01d77ba385ab670729f7b5d95670af3d
```

그 다음 아래 데이터를 이어 붙여 다시 SHA-256을 계산한다.

```text
username || 0x1f || license || 0x1f || sha256(.text) || debug_mask
```

이 digest를 seed로 사용해 `SHA256(seed || counter)`를 counter 0, 1, 2에 대해 계산하고, 총 96바이트 keystream을 만든다. 이 keystream과 `0x140006280`의 ciphertext 96바이트를 XOR하면 flag buffer가 나온다.

마지막으로 프로그램은 `SHA256("LYKN2026" || flag)`의 앞 8바이트를 little-endian 정수로 해석해 `0x2679dda8691cb57d`와 비교한다. 복호화 결과는 이 검증값을 만족한다.

### 익스플로잇

동봉한 `solve.py`는 원본 `KeygenMe.exe`에서 `.text`와 `.rdata`를 직접 읽어 위 과정을 재현한다.

```bash
$ python3 solve.py KeygenMe.exe
username: th3_LYKN_v3nd0r
license: 7211-57C4-CD96-CC26-5B67
text_sha256: 540a6fe0dfa677f2a7b1603fd0db282a01d77ba385ab670729f7b5d95670af3d
flag: LYKNCTF{REDACTED}
check_first8_le: 0x2679dda8691cb57d
```

따라서 GUI에는 다음처럼 입력하면 된다.

```text
Username: th3_LYKN_v3nd0r
License Key: 7211-57C4-CD96-CC26-5B67
```

## 플래그

```text
LYKNCTF{REDACTED}
```

## 추가 파일

| 파일 | 설명 |
|------|------|
| `KeygenMe.exe` | 문제 원본 Windows x64 PE 바이너리 |
| `solve.py` | `KeygenMe.exe`에서 username, license key, flag를 재계산하는 스크립트 |

## 배운 점

이 문제는 단순 keygen처럼 보이지만 anti-debug mask가 license 생성과 flag 복호화 seed 양쪽에 들어간다. 따라서 디버깅 중에 얻은 license가 정상 실행 환경에서는 맞지 않을 수 있고, 반대로 정상 license를 디버깅 환경에서 넣으면 vault 검증이 실패할 수 있다.

또한 `.text` section self-hash가 flag key에 포함되어 있으므로 바이너리를 패치해서 실행 검증하려면 어떤 byte가 hash 대상에 들어가는지 먼저 확인해야 한다. 이런 유형은 입력 검증 루틴만 보는 것보다, 성공 메시지 직전의 최종 복호화와 무결성 검증까지 따라가야 flag를 안정적으로 얻을 수 있다.
