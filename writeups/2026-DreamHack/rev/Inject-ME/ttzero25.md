---
ctf_name: "Dreamhack-Wargame"
challenge_name: "Inject-ME"
category: "rev"
difficulty: "medium"
author: "ttzero25"
date: "2026-06-30"
points: 0
tags: [PE, DLL, WELL512, PRNG, XOR, MessageBoxA]
---

# Inject-ME

## 문제 설명

> `rev.zip` 안에 `prob_rev.dll` 하나가 들어 있다. 이 DLL이 출력하는 플래그를 찾아라.

- 파일: `rev.zip` → `prob_rev.dll`
- 타입: `PE32+ executable (DLL) (GUI) x86-64, for MS Windows`
- MD5: `2505c726b01592184d333748130e95dd`
- SHA-256: `1988f30c9b4982a2e659f0887c65f6ee144eb988becc5669e099449dc3b81c3f`
- 플래그 형식: `DH{...}`

## 풀이

### 분석

익스포트가 없는 DLL이며, 임포트와 strings에서 핵심 단서가 보인다.

- `KERNEL32!GetModuleFileNameA`
- `SHLWAPI!PathFindFileNameA`
- `USER32!MessageBoxA`
- `VCRUNTIME140!strncmp`
- 문자열: `dreamhack.exe`, `flag`

DLL이 로드된 **호스트 실행 파일의 이름**을 검사하고, 조건을 만족하면 `MessageBoxA`로 플래그를 출력하는 구조다. 핵심 로직은 `0x1800011a0` 루틴에 있다.

### 취약점 (핵심 로직)

**1) 프로세스 이름 게이트**

```asm
lea     rdx, [rsp+0xd0]
call    GetModuleFileNameA          ; 호스트 EXE 전체 경로
lea     rcx, [rsp+0xd0]
call    PathFindFileNameA           ; 경로 → 파일명 포인터
mov     r8d, 0xd                    ; 길이 13
lea     rdx, [0x1800031b0]          ; "dreamhack.exe"
call    strncmp
test    eax, eax
jne     <exit>                      ; 이름이 다르면 종료
```

`.rdata`의 `0x1800031b0`에는 `dreamhack.exe\0`가 있다. 즉 이 DLL은 **`dreamhack.exe`라는 이름의 프로세스에 로드되어야** 플래그 로직이 동작한다. (정적으로 계산 가능하므로 실제 실행은 불필요)

**2) 시드 생성**

파일명의 **첫 4바이트**(`"drea"`)를 little-endian dword(`0x61657264`)로 읽어 16개짜리 상태 배열을 만든다.

```asm
loop i = 0..15:
    eax = *(uint32_t*)filename     ; "drea" = 0x61657264
    rol eax, cl                    ; cl = i
    state[i] = eax                 ; state[i] = rol32(0x61657264, i)
```

→ `state[i] = rol32(0x61657264, i)`, `i = 0..15`

**3) PRNG = WELL512**

`0x180001060` 함수는 인덱스(`0x180004640`)와 16-word 상태(`0x180004650`)를 사용하는 PRNG이며, 디스어셈블을 정리하면 정확히 **WELL512**이다. 상수 `0xDA442D24`와 `(idx+13)`, `(idx+9)`, `(idx+15)` 인덱싱이 결정적 시그니처다.

```c
uint32_t WELL512() {
    uint32_t a = state[index];
    uint32_t c = state[(index+13)&15];
    uint32_t b = a ^ c ^ (a<<16) ^ (c<<15);
    c = state[(index+9)&15];
    c ^= (c>>11);
    a = state[index] = b ^ c;
    uint32_t d = a ^ ((a<<5) & 0xDA442D24);
    index = (index+15)&15;
    a = state[index];
    state[index] = a ^ b ^ d ^ (a<<2) ^ (b<<18) ^ (c<<28);
    return state[index];
}
```

### 익스플로잇

복호화 루틴은 다음과 같다.

```asm
; 시드 후 워밍업 100회 (결과 버림)
loop 0x64 times: call WELL512

; 타깃 5개 dword (암호화된 플래그)
[rsp+0x78] = 0x7ed39c88
[rsp+0x7c] = 0x436e8879
[rsp+0x80] = 0x3080393e
[rsp+0x84] = 0x79fd35cc
[rsp+0x88] = 0xf50f300c

; 각 dword를 다음 WELL512 출력과 XOR
loop k = 0..4:
    target[k] ^= WELL512()

; 결과 20바이트를 caption "flag"로 MessageBoxA 출력
lea     rdx, [rsp+0x78]
lea     r8, [0x1800031c0]   ; "flag"
call    MessageBoxA
```

즉 플래그는 **WELL512를 100회 워밍업한 뒤 101~105번째 출력**으로 5개의 타깃 dword를 XOR한 결과다. 알고리즘을 그대로 재구현하면 된다.

```python
M = 0xFFFFFFFF
def rol32(v, c):
    c &= 31
    return ((v << c) | (v >> (32 - c))) & M if c else v & M

# 시드: "dreamhack.exe"의 첫 4바이트 "drea"
seed = int.from_bytes(b"drea", "little")   # 0x61657264
state = [rol32(seed, i) for i in range(16)]
index = 0

def well512():
    global index
    a = state[index]
    c = state[(index + 13) & 15]
    b = (a ^ c ^ ((a << 16) & M) ^ ((c << 15) & M)) & M
    c = state[(index + 9) & 15]
    c ^= (c >> 11)
    a = state[index] = (b ^ c) & M
    d = (a ^ ((a << 5) & 0xDA442D24)) & M
    index = (index + 15) & 15
    a = state[index]
    state[index] = (a ^ b ^ d ^ ((a << 2) & M) ^ ((b << 18) & M) ^ ((c << 28) & M)) & M
    return state[index]

for _ in range(100):          # 워밍업
    well512()

targets = [0x7ed39c88, 0x436e8879, 0x3080393e, 0x79fd35cc, 0xf50f300c]
out = b"".join(((t ^ well512()) & M).to_bytes(4, "little") for t in targets)
print(out.split(b"\x00")[0].decode())
```

실행 결과:

```
DH{reng@r_is_cute}
```

## 플래그

```
DH{reng@r_is_cute}
```

## 배운 점

- DLL이 호스트 프로세스 이름(`dreamhack.exe`)을 키 시드로 사용하는 파일명 의존 안티-분석 기법.
- 표준 PRNG는 마법 상수로 식별할 수 있다 — WELL512의 `0xDA442D24` 마스크가 결정적 단서.
- 시드 → 워밍업 → 출력 스트림 XOR 구조이므로, 실제 실행/디버깅 없이 알고리즘 재구현만으로 정적 복원이 가능하다.
