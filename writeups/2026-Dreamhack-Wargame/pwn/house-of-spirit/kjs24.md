---
ctf_name: "Dreamhack-Wargame"
challenge_name: "house_of_spirit"
category: "pwn"
difficulty: "medium"
author: "kjs24"
date: "2026-08-19"
points:
tags: [ELF, x86-64, heap, House of Spirit, tcache, stack-leak]
---

# house_of_spirit

## 문제 설명

Dreamhack의 힙 기법 실습 문제이다. 사용자 이름을 입력받은 뒤 생성, 삭제,
종료 메뉴를 제공한다.

- 제공 파일: `house_of_spirit`, `house_of_spirit.c`
- 원격 접속 정보: `host3.dreamhack.games:8575`
- 첨부한 원본 풀이 스크립트: [payload.py](payload.py)

핵심은 스택의 `name` 주소를 출력해 주는 정보 누출과, 사용자가 입력한 주소를
검증 없이 `free()`에 전달하는 취약점이다. 이 둘을 결합해 스택에 가짜 청크를
만들고, `malloc()`이 스택 영역을 반환하도록 유도한다.

## 보호 기법

```text
Arch:     amd64
RELRO:    Partial RELRO
Canary:   없음
NX:       활성화
PIE:      비활성화
```

NX가 활성화되어 있으므로 셸코드를 실행하지 않는다. PIE가 비활성화되어 있는
덕분에 `get_shell()`의 주소는 항상 `0x400940`이다.

## 풀이

### 스택 주소 누출

```c
char name[32];

read(0, name, sizeof(name)-1);
printf("%p: %s\n", name, name);
```

`%p`가 `name` 버퍼의 스택 주소를 그대로 출력한다. 이 값을 `name_addr`라고
하면 이후 가짜 청크와 반환 주소의 위치를 정확히 계산할 수 있다.

### 임의 주소 free

```c
printf("Addr: ");
scanf("%ld", &addr);
free(addr);
```

삭제 기능은 `ptr[]`에 저장된 할당 주소를 사용하지 않고, 입력한 `addr`을
그대로 `free()`에 넘긴다. 즉, 올바른 청크 형태로 보이는 스택 주소를
`free()`할 수 있다.

### 스택에 가짜 청크 만들기

64비트 glibc 청크의 헤더와 사용자 영역은 다음과 같다.

```text
+0x00  prev_size
+0x08  size
+0x10  사용자 영역  <- malloc()이 반환하는 주소
```

처음 입력하는 `name`에 다음 바이트열을 쓴다.

```python
fake_chunk = b"A" * 0x10 + p64(0) + p64(0x31)
p.sendafter(b"name: ", fake_chunk[:-1])
```

이로써 `name_addr + 0x10`부터 가짜 청크 헤더가 놓인다.

```text
name_addr + 0x10 : prev_size = 0
name_addr + 0x18 : size      = 0x31
name_addr + 0x20 : 가짜 청크의 사용자 영역
```

`0x31`은 청크 크기 `0x30`과 `PREV_INUSE` 비트의 조합이다.
`free(name_addr + 0x20)`을 호출하면 glibc는 `name_addr + 0x10`을 헤더로
해석하고, 가짜 청크를 해당 크기의 tcache/fastbin에 연결한다. 바로 뒤에
`malloc(0x20)`을 호출하면 같은 크기의 청크를 꺼내므로 반환값은
`name_addr + 0x20`이 된다.

`read()`는 31바이트만 받는다. 따라서 가짜 헤더의 마지막 널 바이트는
전송하지 않는데, `name`은 미리 `memset()`으로 0으로 초기화되므로
`p64(0x31)`의 마지막 바이트는 그대로 0으로 남는다. 이 방법은 다음 메뉴의
`scanf()`가 가짜 청크의 남은 바이트를 입력으로 읽는 일도 방지한다.

### 반환 주소 덮기

`main`의 스택 프레임은 디스어셈블 결과 다음과 같이 배치되어 있다.

```text
낮은 주소
name_addr + 0x20 == rbp - 0x10  <- malloc(0x20)의 반환 주소
name_addr + 0x2c == rbp - 0x04  <- i
name_addr + 0x30 == rbp + 0x00  <- 저장된 RBP
name_addr + 0x38 == rbp + 0x08  <- 저장된 RIP
높은 주소
```

따라서 `malloc(0x20)`이 반환한 스택 주소에 정확히 32바이트를 쓰면 저장된
RIP까지 도달한다. `i`는 초기화되지 않은 지역 변수이므로, 페이로드에서
0으로 덮어 이후의 `i++`도 정상적인 값이 되게 한다.

```python
payload = b"A" * 0xc
payload += p32(0)             # i
payload += b"B" * 8          # 저장된 RBP
payload += p64(get_shell_addr) # 저장된 RIP
```

마지막으로 메뉴 `3`을 선택하면 `main`이 반환한다. 저장된 RIP에 넣어 둔
`get_shell()`이 실행되고, 이 함수의 `execve("/bin/sh", NULL, NULL)`로
셸을 얻는다.

### 전체 흐름

1. `name`을 입력하고 출력된 스택 주소 `name_addr`를 읽는다.
2. `name_addr + 0x20`을 `free()`하여 가짜 `0x30` 청크를 bin에 넣는다.
3. 크기 32를 생성하여 `malloc(0x20)`이 스택의 가짜 청크를 반환하게 한다.
4. 반환된 사용자 영역에 `i`, 저장된 RBP, 저장된 RIP 순으로 써서 RIP를 `get_shell()`로 덮는다.
5. 메뉴 `3`으로 `main`에서 반환해 셸을 실행한다.

## 원본 페이로드

풀이에 사용한 스크립트 원본은 같은 디렉터리의 [payload.py](payload.py)에
수정 없이 첨부했다.

## 플래그

```text
DH{REDACTED}
```

## 배운 점

House of Spirit은 힙에 실제로 할당된 청크만 재사용하는 것이 아니라,
`free()`가 유효한 청크 메타데이터로 해석할 수 있는 위치를 재사용한다는 점을
이용한다. 이 문제에서는 스택 주소 누출로 가짜 청크의 위치를 알고 있고 임의
`free()`가 가능하므로, 힙 할당을 스택 쓰기 원시로 바꿀 수 있다.
